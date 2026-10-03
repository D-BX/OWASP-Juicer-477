// Client-side logic for the login form.
// NOTE: client-side validation is a UX convenience only. It can be bypassed
// (curl, Postman, dev tools), so the server MUST validate independently.

const form = document.getElementById("login-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const result = document.getElementById("result");

// The required validation function: email must contain "@",
// password must be at least 8 characters, and neither may be empty.
function validate(email, password) {
  if (!email || !password) return "Both fields are required.";
  if (!email.includes("@")) return 'Email must contain "@".';
  if (password.length < 8) return "Password must be at least 8 characters.";
  return null; // valid
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = emailInput.value.trim();
  const password = passwordInput.value;

  // 1) Client-side validation (blocks empty / malformed submissions early)
  const clientError = validate(email, password);
  if (clientError) {
    result.textContent = clientError; // safe: textContent never parses HTML
    return;
  }

  // 2) Send to server, which validates again and performs the real login
  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();

    // ----------------------------------------------------------------------
    // INTENTIONALLY VULNERABLE (for Part 3 of the assignment):
    // The server's message can contain raw user input. Rendering it with
    // innerHTML lets the browser PARSE that input as HTML -> DOM-based XSS.
    //
    // SECURE FIX (see README "Part 3"): use textContent instead, e.g.
    //   result.textContent = data.ok ? data.message : data.error;
    // ----------------------------------------------------------------------
    result.innerHTML = data.ok ? data.message : data.error;
  } catch (err) {
    result.textContent = "Something went wrong. Please try again.";
  }
});
