const form = document.querySelector('#hash-form');
const passwordInput = document.querySelector('#password');
const confirmPasswordInput = document.querySelector('#confirm-password');
const memoryInput = document.querySelector('#memory');
const iterationsInput = document.querySelector('#iterations');
const parallelismInput = document.querySelector('#parallelism');
const generateButton = document.querySelector('#generate');
const togglePasswordButton = document.querySelector('#toggle-password');
const message = document.querySelector('#message');
const resultSection = document.querySelector('#result-section');
const hashOutput = document.querySelector('#hash-output');
const copyButton = document.querySelector('#copy');

function setMessage(text, isError = false) {
  message.textContent = text;
  message.classList.toggle('error', isError);
}

togglePasswordButton.addEventListener('click', () => {
  const showing = passwordInput.type === 'text';
  passwordInput.type = showing ? 'password' : 'text';
  togglePasswordButton.textContent = showing ? 'Show' : 'Hide';
  togglePasswordButton.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  resultSection.hidden = true;
  hashOutput.value = '';

  const password = passwordInput.value;
  const confirmation = confirmPasswordInput.value;
  const memory = Number(memoryInput.value);
  const iterations = Number(iterationsInput.value);
  const parallelism = Number(parallelismInput.value);

  if (password.length < 12) {
    setMessage('Use a password with at least 12 characters.', true);
    return;
  }

  if (password !== confirmation) {
    setMessage('The passwords do not match.', true);
    return;
  }

  if (!window.argon2) {
    setMessage('The Argon2 library did not load. Check your internet connection and reload.', true);
    return;
  }

  generateButton.disabled = true;
  generateButton.textContent = 'Generating hash…';
  setMessage('Hashing locally in your browser…');

  try {
    const result = await window.argon2.hash({
      pass: password,
      salt: window.crypto.getRandomValues(new Uint8Array(16)),
      time: iterations,
      mem: memory,
      parallelism,
      hashLen: 32,
      type: window.argon2.ArgonType.Argon2id,
    });

    hashOutput.value = result.encoded;
    resultSection.hidden = false;
    setMessage('Hash generated. Copy the complete value into password_hash.');
  } catch (error) {
    console.error('Argon2 hashing failed', error);
    setMessage('Hash generation failed. Try lower memory or reload the page.', true);
  } finally {
    passwordInput.value = '';
    confirmPasswordInput.value = '';
    generateButton.disabled = false;
    generateButton.textContent = 'Generate Argon2id hash';
  }
});

copyButton.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(hashOutput.value);
    copyButton.textContent = 'Copied';
    window.setTimeout(() => {
      copyButton.textContent = 'Copy';
    }, 1800);
  } catch {
    hashOutput.focus();
    hashOutput.select();
    setMessage('Select and copy the hash manually.', true);
  }
});
