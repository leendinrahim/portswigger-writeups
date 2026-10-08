# PortSwigger Lab: Reflected XSS into Attribute with Angle Brackets HTML-Encoded

## 📌 Executive Summary

In web application security, XSS mitigation often focuses on preventing HTML tags such as `<script>`. However, a vulnerability can still occur when characters are handled incorrectly depending on the context in which user input is reflected (*Context-Aware Encoding Failure*).

This write-up analyzes how a web application correctly protects the *HTML Body* context (inside an `<h1>` element) but fails to properly protect the *HTML Attribute* context (inside `<input value="...">`). This makes **Reflected Cross-Site Scripting (XSS)** possible through an *Attribute Breakout*.

---

## 🛠️ Environment & Scenario

- **Platform:** PortSwigger Web Security Academy
- **Vulnerability Type:** Reflected Cross-Site Scripting (XSS)
- **Target Contexts:**
  1. *HTML Body Context* (`<h1>0 search results for '...'</h1>`)
  2. *HTML Attribute Context* (`<input type="text" value="...">`)

---

## 🔎 Methodology: Finding the Reflection Point

Before fuzzing special characters, the first step is to identify where the input is reflected in the response. A simple way to do this is to send a unique *canary* string that is easy to find with `Ctrl+F`, for example:

```text
xsscanary123
```

After locating the reflection points, the input appeared twice: once inside the `<h1>` element and once inside the `value` attribute of the search input. I then fuzzed special characters in each context to determine which characters were being encoded.

---

## 🔍 Technical Analysis & Character Inconsistency

The following token was used for fuzzing:

`well" ' <>; \ /`

### 1. Behavior in the HTML Body (`<h1>`)

The server applies strict *HTML Entity Encoding* to special characters:

- `<` and `>` are converted to `&lt;` and `&gt;`
- `"` is converted to `&quot;`
- `'` is converted to `&apos;`

**Response HTML:**

```html
<h1>0 search results for 'well&quot; &apos; &lt;&gt; \ /'</h1>
```

**Status: SAFE — the input remains plain text.**

### 2. Behavior in the HTML Attribute (`<input value="...">`)

A critical inconsistency appears in the search input. Although angle brackets (`<>`) are still encoded, the server **leaves quotation marks unencoded**:

- `<` and `>` are converted to `&lt;` and `&gt;`
- `"` remains as `"`
- `'` remains as `'`

**Response HTML:**

```html
<input type="text" placeholder='Search the blog...' name=search value="well" ' &lt;&gt; \ /">
```

**Status: VULNERABLE — the attribute structure can be broken.**

> **Note:** The `name=search` attribute is also written without quotation marks. Unquoted attributes can be vulnerable to breakout through whitespace, so this is worth mentioning as an additional observation.

---

## 🚀 Exploitation Vector (Attribute Breakout)

Because the double quote (`"`) is not filtered inside the `<input>` element, we do not need `<` or `>` (which are already blocked) to trigger XSS. We only need to break out of the `value="..."` attribute.

### 1. Payload Construction

The payload used was:

```text
" onmouseover="alert(1)
```

### 2. Reconstructed Response

When the payload is reflected, the HTML becomes:

```html
<input type="text" placeholder='Search the blog...' name=search value="" onmouseover="alert(1)">
```

**How it works:**

1. The first `"` prematurely closes the `value` attribute (`value=""`).
2. The following whitespace separates the next attribute.
3. `onmouseover="alert(1)"` is interpreted by the browser as a valid event-handler attribute on the `<input>` element.

When the user moves the mouse over the search field, the browser executes `alert(1)`.

### 3. Payload Limitation

`onmouseover` requires user interaction because the victim has to hover over the element. If execution without explicit interaction is desired, an alternative is to use `autofocus` together with `onfocus`:

```text
" autofocus onfocus="alert(1)
```

The `autofocus` attribute causes the field to receive focus when the page loads, which triggers the `onfocus` handler.

---

## 💥 Impact

This is a **Reflected XSS** vulnerability, meaning the payload is not permanently stored on the server. The victim must access a URL containing the malicious input, typically through a link.

Depending on the application's functionality and the victim's privileges, reflected XSS can potentially allow an attacker to:

- Perform actions in the context of the victim's session
- Modify application data or interact with functionality available to the victim
- Present convincing phishing content within the trusted origin

The severity depends on what the victim's session can access. The impact should therefore be assessed based on the application's actual privileges and functionality.

---

## 💡 Key Takeaway & Root Cause

The vulnerability occurs because the application treats encoding as if one rule is sufficient for every reflection context. In this case, encoding `<` and `>` without encoding quotation marks is not sufficient for data reflected inside an HTML attribute.

In a secure web application, the **context determines the appropriate encoding strategy**:

- In normal HTML text content, special HTML characters such as `<`, `>`, and `&` must be encoded.
- In HTML attributes such as `value`, quotation marks must also be encoded (`"` → `&quot;`, `'` → `&#x27;`) to prevent attribute breakout.
- For URL-valued attributes such as `href` and `src`, HTML encoding alone is not sufficient. URL validation is also required to prevent dangerous schemes such as `javascript:`.

---

## 🛡️ Remediation

Ensure that user-controlled data reflected into HTML attributes is properly encoded for the relevant context. In PHP, for example, `ENT_QUOTES` can be used:

```php
// Encode angle brackets as well as single and double quotes
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
```

With this fix, a `"` character from the input is converted to `&quot;`. The browser decodes the entity as data inside the attribute rather than treating it as HTML syntax that terminates the attribute, preventing the payload from breaking out.

Additional defense-in-depth measures:

- **Quote all HTML attributes** (`name="search"` instead of `name=search`).
- Use a properly configured **Content Security Policy (CSP)** to reduce the impact of XSS and block inline event handlers where appropriate.
