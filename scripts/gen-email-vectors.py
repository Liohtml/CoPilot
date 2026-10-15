"""Generate `EmailStr` vectors for copilot-web's port of pydantic's email validation.

    backend/.venv/bin/python -I scripts/gen-email-vectors.py \
        > crates/copilot-web/src/email_vectors.json

Each case is what `pydantic.networks.validate_email` (pretty-name parsing, strip,
`email_validator.validate_email(check_deliverability=False)`) makes of an input: the
normalized address, or the error message. ASCII input is the contract; the handful of
internationalized cases pin normalization of valid addresses.
"""
import json
import sys

import email_validator
import pydantic
import pydantic_core
from pydantic.networks import validate_email

CASES = [
    # valid
    "a@b.com",
    "Foo@Example.COM",
    "first.last@sub.example.co.uk",
    "user+tag@x.io",
    "x_y-z@a-b.c-d.org",
    "a!#$%&'*+-/=?^_`{|}~@x.com",
    "INFO@x.com",
    "Postmaster@X.COM",
    "John <j@x.com>",
    "John Q Public <j@x.com>",
    '"John Doe" <j@x.com>',
    '"J \\"Q\\" D" <j@x.com>',
    "  a@b.com  ",
    "\ta@b.com\n",
    "<j@x.com>",
    "a@123.com",
    "a@x.museum",
    "x" * 65 + "@x.com",
    "a@" + "b" * 63 + ".com",
    "a@xn--mnchen-3ya.de",
    "a@münchen.de",
    "a@MÜNCHEN.DE",
    "ä@ö.de",
    "té@x.com",
    "a@x。com",
    "a@ｘ.com",
    # invalid
    "",
    " ",
    "nope",
    "@x.com",
    "a@",
    "a@b",
    "a@b.c",
    "a@b.local",
    "a@sub.localhost",
    "a@x.test",
    "a@x.invalid",
    "a@x.onion",
    "a@1.in-addr.arpa",
    "a@test",
    "a..b@x.com",
    ".a@x.com",
    "a.@x.com",
    "a b@x.com",
    "a@b c.com",
    "a@-x.com",
    "a@x-.com",
    "a@x..com",
    "a@.x.com",
    "a@x.com.",
    "a@x.com-",
    "a@x.-com",
    "a@ab--cd.com",
    "a@x.c0m",
    "a@x.1",
    "a@x_y.com",
    "a@x/y.com",
    "a@b@c.com",
    "a<b@c.com",
    "John <j@x.com",
    "John <j@x.com> x",
    "Jo.hn <j@x.com>",
    "Jo(hn) <j@x.com>",
    '"unterminated <j@x.com>',
    "a\\b@x.com",
    'a"b@x.com',
    '"quoted"@x.com',
    '"a b"@x.com',
    '"a"b@x.com',
    "a@[1.2.3.4]",
    "a@[IPv6:::1]",
    "a@[foo]",
    "a@[foo:bar]",
    "a@[1.2.3]",
    "a@[]",
    "a b@x.com",
    "a​@x.com",
    "a@x .com",
    "a@x.com​",
    "a\x00@x.com",
    "a\x7f@x.com",
    "a\n@x.com",
    "a@x.c\x01m",
    "a @x.com",
    "a‮@x.com",
    "a＠x.com",
    "a﹫x.com",
    "́a@x.com",
    "x" * 250 + "@x.com",
    "a@" + "b" * 64 + ".com",
    "a@" + ".".join(["b" * 60] * 5) + ".com",
    "x" * 2049,
    "a@x.com" + "m" * 250,
    "a@xn--.com",
    "a@xn--a.com",
    "a@xn--zz-.com",
    "John <a@b.local>",
    "a@b,com",
    "a;b@x.com",
    "a@x.cóm",
]


def main():
    out = []
    for value in CASES:
        try:
            _, email = validate_email(value)
            out.append({"input": value, "email": email})
        except pydantic_core.PydanticCustomError as e:
            out.append({"input": value, "error": str(e)})
    doc = {
        "pydantic": pydantic.__version__,
        "email_validator": email_validator.__version__,
        "cases": out,
    }
    json.dump(doc, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


main()
