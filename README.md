# Juice Shop Login Clone

A minimal login page modeled on [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), built for a cybersecurity risk assignment. It demonstrates **client-side and server-side validation**, **parameterized SQL queries** (to defeat SQL injection), and **bcrypt password hashing**.

> ⚠️ This project contains **one intentional vulnerability** (a DOM-based XSS) that is used to demonstrate an attack and its fix in Part 3. It is clearly commented in the code and **must not be used in production.**

## What it does

- Serves a Juice Shop–style login form (email + password).
- **Client-side** (`app.js`): blocks empty submissions and checks that the email contains `@` and the password is at least 8 characters before sending anything.
- **Server-side** (`server.js`): repeats the same validation (never trusting the client), looks the user up with a **parameterized** SQLite query, and verifies the password with **bcrypt**.
- Stores passwords only as bcrypt hashes — never plaintext.

### Seeded test account

| Email | Password |
|-------|----------|
| `admin@juice-sh.op` | `admin123!` |

## How to run

Requires **Node.js 22.5+** (24+ recommended) — the app uses Node's built-in SQLite, so there is nothing to compile and no native modules to install.

```bash
npm install
npm start
```

Then open **http://localhost:3000**.

## Project structure

```
juice-shop-login-clone/
├── index.html    # the form
├── style.css     # styling
├── app.js        # client-side validation + request
├── server.js     # Express server, validation, bcrypt, parameterized SQL
├── package.json
└── README.md
```

## Security notes

- **SQL injection:** the login query uses a `?` placeholder, so input such as `' OR 1=1--` is bound as data and matches nothing.
- **Password handling:** passwords are hashed with `bcrypt` (cost factor 12) before storage and compared with `bcrypt.compareSync`.
- **Validation:** performed on both the client (UX) and the server (authoritative).

## Part 3 — the intentional vulnerability

**Bug:** `app.js` renders the server's response with `result.innerHTML = ...`. Because that message can contain raw user input, a crafted email is parsed as HTML.

**Reproduce it:**
1. In the email field, enter: `<img src=x onerror=alert(document.domain)>@test.com`
2. Enter any password with 8+ characters.
3. Submit. The input passes validation (it contains `@` and is long enough), the server returns a "Login failed for …" message containing the raw input, and `innerHTML` parses the `<img>` tag. Its broken `src` triggers `onerror`, running the JavaScript — an alert box appears.

**Fix:** render untrusted text with `textContent`, which never parses HTML:

```js
// vulnerable
result.innerHTML = data.ok ? data.message : data.error;
// fixed
result.textContent = data.ok ? data.message : data.error;
```

For defense in depth, also encode output server-side and send a restrictive `Content-Security-Policy` header.
