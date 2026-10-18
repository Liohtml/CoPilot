/* The checks and the fill of Playwright's injected script (playwright-core
   1.59.1, Apache-2.0) that `page.fill` and `page.click` run on the first
   element a CSS selector matches: visible, enabled (and editable to fill;
   stable over an animation frame to click), then the fill's own rules. */
async (selector, action, value) => {
  const element = document.querySelector(selector);
  if (!element || !element.isConnected)
    return "error:notconnected";
  const visibleBox = (el) => {
    const style = getComputedStyle(el);
    if (!style)
      return true;
    if (style.display === "contents") {
      for (let child = el.firstChild; child; child = child.nextSibling) {
        if (child.nodeType === 1 && visibleBox(child))
          return true;
        if (child.nodeType === 3) {
          const range = child.ownerDocument.createRange();
          range.selectNode(child);
          const r = range.getBoundingClientRect();
          if (r.width > 0 && r.height > 0)
            return true;
        }
      }
      return false;
    }
    if (Element.prototype.checkVisibility && !el.checkVisibility())
      return false;
    if (style.visibility !== "visible")
      return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  if (!visibleBox(element))
    return "error:notvisible";
  const tag = element.tagName.toUpperCase();
  const nativeControl = ["BUTTON", "INPUT", "SELECT", "TEXTAREA", "OPTION", "OPTGROUP"].includes(tag);
  const fieldSet = element.closest("FIELDSET[DISABLED]");
  const legend = fieldSet ? fieldSet.querySelector(":scope > LEGEND") : null;
  const inDisabledFieldSet = !!fieldSet && !(legend && legend.contains(element));
  const disabled = (nativeControl && (element.hasAttribute("disabled") || inDisabledFieldSet))
    || (element.getAttribute("aria-disabled") || "").toLowerCase() === "true";
  if (disabled)
    return "error:notenabled";
  if (action === "click") {
    const before = element.getBoundingClientRect();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    const after = element.getBoundingClientRect();
    if (before.x !== after.x || before.y !== after.y || before.width !== after.width || before.height !== after.height)
      return "error:notstable";
    return element;
  }
  if (["INPUT", "TEXTAREA", "SELECT"].includes(tag)) {
    if (element.hasAttribute("readonly"))
      return "error:noteditable";
  } else if (!element.isContentEditable) {
    throw new Error("Element is not an <input>, <textarea>, <select> or [contenteditable] and does not have a role allowing [aria-readonly]");
  }
  if (tag === "INPUT") {
    const type = element.type.toLowerCase();
    const setValue = new Set(["color", "date", "time", "datetime-local", "month", "range", "week"]);
    const typeInto = new Set(["", "email", "number", "password", "search", "tel", "text", "url"]);
    if (!typeInto.has(type) && !setValue.has(type))
      throw new Error(`Input of type "${type}" cannot be filled`);
    if (type === "number") {
      value = value.trim();
      if (isNaN(Number(value)))
        throw new Error("Cannot type text into input[type=number]");
    }
    if (type === "color")
      value = value.toLowerCase();
    if (setValue.has(type)) {
      value = value.trim();
      element.focus();
      element.value = value;
      if (element.value !== value)
        throw new Error("Malformed value");
      element.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
      return "done";
    }
    element.select();
    element.focus();
    return "needsinput";
  }
  if (tag === "TEXTAREA") {
    element.selectionStart = 0;
    element.selectionEnd = element.value.length;
    element.focus();
    return "needsinput";
  }
  if (tag === "SELECT")
    throw new Error("Element is not an <input>, <textarea> or [contenteditable] element");
  element.focus();
  const range = element.ownerDocument.createRange();
  range.selectNodeContents(element);
  const selection = element.ownerDocument.defaultView.getSelection();
  if (selection) {
    selection.removeAllRanges();
    selection.addRange(range);
  }
  return "needsinput";
}
