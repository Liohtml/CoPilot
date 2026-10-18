//! Starting the browser as Playwright's `launchProcess` starts it: the
//! executable from Playwright's browser registry (or `COPILOT_CHROMIUM`),
//! `chromiumSwitches` and the headless flags, a fresh
//! `playwright_chromiumdev_profile-XXXXXX` profile and a
//! `playwright-artifacts-XXXXXX` downloads directory in the temporary
//! directory, removed again on close, and the protocol on fds 3 and 4.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use rand::Rng as _;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

use super::Error;

/// `chromiumSwitches(assistantMode=false, channel=undefined)`.
const SWITCHES: &[&str] = &[
    "--disable-field-trial-config",
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-back-forward-cache",
    "--disable-breakpad",
    "--disable-client-side-phishing-detection",
    "--disable-component-extensions-with-background-pages",
    "--disable-component-update",
    "--no-default-browser-check",
    "--disable-default-apps",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-features=AvoidUnnecessaryBeforeUnloadCheckSync,BoundaryEventDispatchTracksNodeRemoval,DestroyProfileOnBrowserClose,DialMediaRouteProvider,GlobalMediaControls,HttpsUpgrades,LensOverlay,MediaRouter,PaintHolding,ThirdPartyStoragePartitioning,Translate,AutoDeElevate,RenderDocument,OptimizationHints",
    "--enable-features=CDPScreenshotNewSurface",
    "--allow-pre-commit-input",
    "--disable-hang-monitor",
    "--disable-ipc-flooding-protection",
    "--disable-popup-blocking",
    "--disable-prompt-on-repost",
    "--disable-renderer-backgrounding",
    "--force-color-profile=srgb",
    "--metrics-recording-only",
    "--no-first-run",
    "--password-store=basic",
    "--use-mock-keychain",
    "--no-service-autorun",
    "--export-tagged-pdf",
    "--disable-search-engine-choice-screen",
    "--unsafely-disable-devtools-self-xss-warnings",
    "--edge-skip-compat-layer-relaunch",
    "--enable-automation",
    "--disable-infobars",
    "--disable-search-engine-choice-screen",
    "--disable-sync",
    // `_innerDefaultArgs`: always, then for `headless`, then without
    // `chromiumSandbox`.
    "--enable-unsafe-swiftshader",
    "--headless",
    "--hide-scrollbars",
    "--mute-audio",
    "--blink-settings=primaryHoverType=2,availableHoverTypes=2,primaryPointerType=4,availablePointerTypes=4",
    "--no-sandbox",
];

/// Moves the pipe ends the child gets on 0 and 1 to 3 and 4, where
/// `--remote-debugging-pipe` reads and writes, then runs the browser with
/// its own arguments (`$0` is the executable).
const PIPE_SHIM: &str = "exec \"$0\" \"$@\" 3<&0 4>&1 0</dev/null 1>&2";

/// The argument list after the switches.
pub fn arguments(user_data_dir: &Path) -> Vec<String> {
    let mut args: Vec<String> = SWITCHES.iter().map(|s| (*s).to_string()).collect();
    args.push(format!("--user-data-dir={}", user_data_dir.display()));
    args.push("--remote-debugging-pipe".into());
    args.push("--no-startup-window".into());
    args
}

/// `os.tmpdir()` (Node): `TMPDIR`, `TMP`, `TEMP`, else `/tmp`.
pub fn node_tmpdir() -> PathBuf {
    for var in ["TMPDIR", "TMP", "TEMP"] {
        if let Some(dir) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            let mut p = PathBuf::from(dir);
            // Node drops one trailing separator.
            if p.as_os_str().len() > 1 && p.to_string_lossy().ends_with('/') {
                p = PathBuf::from(p.to_string_lossy().trim_end_matches('/'));
            }
            return p;
        }
    }
    PathBuf::from("/tmp")
}

/// `fs.mkdtemp(prefix)`: six characters of `[A-Za-z0-9]` appended.
pub fn mkdtemp(dir: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut last = None;
    for _ in 0..100 {
        let mut name = String::from(prefix);
        let mut rng = rand::thread_rng();
        for _ in 0..6 {
            name.push(char::from(CHARS[rng.gen_range(0..CHARS.len())]));
        }
        let path = dir.join(name);
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("mkdtemp failed")))
}

/// The two layouts of a `chromium_headless_shell-<revision>` directory:
/// Chrome for Testing's (linux-x64) and Playwright's own build's.
const SHELL_PATHS: [&str; 2] = [
    "chrome-headless-shell-linux64/chrome-headless-shell",
    "chrome-linux/headless_shell",
];

/// Playwright's registry directory: `PLAYWRIGHT_BROWSERS_PATH`, else
/// `$XDG_CACHE_HOME/ms-playwright`, else `~/.cache/ms-playwright`.
fn registry_dir() -> Option<PathBuf> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
    if let Some(p) = env("PLAYWRIGHT_BROWSERS_PATH").filter(|p| p != "0") {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = env("XDG_CACHE_HOME") {
        return Some(PathBuf::from(p).join("ms-playwright"));
    }
    env("HOME").map(|h| PathBuf::from(h).join(".cache").join("ms-playwright"))
}

/// The browser `chromium.launch(headless=True)` runs: `COPILOT_CHROMIUM`
/// when set, else the newest `chromium_headless_shell-*` of Playwright's
/// registry (the image installs Playwright 1.59's, revision 1217).
pub fn find_executable() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("COPILOT_CHROMIUM").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let dir = registry_dir()?;
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in std::fs::read_dir(&dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(revision) = name
            .strip_prefix("chromium_headless_shell-")
            .and_then(|r| r.parse::<u64>().ok())
        else {
            continue;
        };
        let Some(exe) = SHELL_PATHS
            .iter()
            .map(|p| entry.path().join(p))
            .find(|p| p.is_file())
        else {
            continue;
        };
        if best.as_ref().is_none_or(|(r, _)| revision > *r) {
            best = Some((revision, exe));
        }
    }
    best.map(|(_, p)| p)
}

/// A started browser process and its pipes.
pub struct Launched {
    /// The process (`/bin/sh`, which became the browser).
    pub child: Child,
    /// Commands to the browser (its fd 3).
    pub stdin: ChildStdin,
    /// Messages from the browser (its fd 4).
    pub stdout: ChildStdout,
    /// Its stdout and stderr.
    pub stderr: ChildStderr,
    /// The profile and artifacts directories, removed on close.
    pub dirs: Vec<PathBuf>,
}

/// Start `executable` with Playwright's arguments.
pub fn spawn(executable: &Path) -> Result<Launched, Error> {
    let tmp = node_tmpdir();
    let artifacts = mkdtemp(&tmp, "playwright-artifacts-")?;
    let profile = match mkdtemp(&tmp, "playwright_chromiumdev_profile-") {
        Ok(p) => p,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&artifacts);
            return Err(e.into());
        }
    };
    let dirs = vec![artifacts, profile.clone()];
    if !executable.is_file() {
        for d in &dirs {
            let _ = std::fs::remove_dir_all(d);
        }
        return Err(Error::Launch(format!(
            "Executable doesn't exist at {}",
            executable.display()
        )));
    }
    let spawned = Command::new("/bin/sh")
        .arg("-c")
        .arg(PIPE_SHIM)
        .arg(executable)
        .args(arguments(&profile))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            for d in &dirs {
                let _ = std::fs::remove_dir_all(d);
            }
            return Err(Error::Launch(e.to_string()));
        }
    };
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(Error::Launch("no pipes to the browser".into()));
    };
    Ok(Launched {
        child,
        stdin,
        stdout,
        stderr,
        dirs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_end_like_playwrights() {
        let args = arguments(Path::new("/tmp/playwright_chromiumdev_profile-abcdef"));
        assert_eq!(args.len(), 44);
        assert_eq!(args[0], "--disable-field-trial-config");
        assert_eq!(
            &args[args.len() - 4..],
            [
                "--no-sandbox",
                "--user-data-dir=/tmp/playwright_chromiumdev_profile-abcdef",
                "--remote-debugging-pipe",
                "--no-startup-window"
            ]
        );
    }

    #[test]
    fn mkdtemp_appends_six_characters() {
        let dir = std::env::temp_dir();
        let p = mkdtemp(&dir, "copilot-mkdtemp-test-").unwrap();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name.len(), "copilot-mkdtemp-test-".len() + 6);
        assert!(p.is_dir());
        std::fs::remove_dir(&p).unwrap();
    }
}
