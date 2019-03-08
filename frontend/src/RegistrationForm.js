import React, { useState } from "react";
import sha1 from "simple-sha1";

function RegistrationForm() {
  const [username, setUserName] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [breaches, setBreaches] = useState(0);
  return (
    <div>
      <form
        onSubmit={e => submit(e, username, password, password2, setBreaches)}
      >
        <label>Username:</label>
        <input
          value={username}
          onChange={e => setUserName(e.target.value)}
          placeholder="mustermax"
          type="text"
          name="username"
        />
        <label>Password:</label>
        <input
          value={password}
          onChange={e => setPassword(e.target.value)}
          placeholder="password"
          type="password"
          name="password"
        />
        <label>Repeat Password:</label>
        <input
          value={password2}
          onChange={e => setPassword2(e.target.value)}
          placeholder="repeat password"
          type="password"
          name="password"
        />
        <input type="submit" value="Submit" />
      </form>
      <div>{breaches}</div>
    </div>
  );
}

function submit(e, username, password, password2, cb) {
  e.preventDefault();
  verifyPassword(password, password2)
    .then(() => verifyUsername(username))
    .then(() => console.log("submit me!"))
    .catch(error => {
      console.error(error);
      cb(error.message);
    });
}

/**
 * Verifies the given username.
 * Throws an error if the username fails the verification.
 *
 * @param {string} username the username
 *
 */
function verifyUsername(username) {
  if (!username || username.length < 1) {
    throw new Error("Username was not entered");
  }
}

/**
 * Verifies the given password inputs. Rejects if
 * the given passwords fail the verification.
 *
 * @param {string} password1 the password
 * @param {string} password2 the repeated password
 * @returns {Promise<void>} a promise that resolves if the given input was sucessfully verified.
 */
async function verifyPassword(password1, password2) {
  if (password1 !== password2) {
    throw new Error("Password and repeated password are not equal. Typo?");
  }

  if (!password1 || password1.length <= 4) {
    throw new Error("Password was too short, choose a longer password");
  }

  if (password1.length > 160) {
    throw new Error(
      "Passwords was too long, 160 characters should be reasonable :)"
    );
  }

  const numberOfBreaches = await passwordCheck(password1);
  if (numberOfBreaches > 0) {
    throw new Error(
      `This password was exposed in ${numberOfBreaches} database breaches and is therefore not a secure password`
    );
  }
}

/**
 * Checks wether the given password was exposed in known
 * database breaches. This is done by sending a partial SHA-1
 * hash to the pwnedpasswords api.
 *
 * Returns the number of known breaches this password was
 * exposed in.
 *
 * @param {string} password the password string
 * @returns {Promise<number>} the number of known breaches this password was
 * exposed in.
 *
 * @see https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange
 */
async function passwordCheck(password) {
  const hash = sha1.sync(password);
  const start = hash.substring(0, 5);
  const rest = hash.substring(5).toUpperCase();

  const response = await fetch(`https://api.pwnedpasswords.com/range/${start}`);
  const results = await response.text();
  let numberOfBreaches = 0;
  for (const line of results.split("\n")) {
    if (line.startsWith(rest)) {
      numberOfBreaches = line.split(":")[1];
    }
  }

  return numberOfBreaches;
}

export default RegistrationForm;
