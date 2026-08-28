const form = document.querySelector('#hash-form');
const passwordInput = document.querySelector('#password');
const memoryInput = document.querySelector('#memory');
const iterationsInput = document.querySelector('#iterations');
const parallelismInput = document.querySelector('#parallelism');
const generateButton = document.querySelector('#generate');
const togglePasswordButton = document.querySelector('#toggle-password');
const message = document.querySelector('#message');
const resultSection = document.querySelector('#result-section');
const hashOutput = document.querySelector('#hash-output');
const copyButton = document.querySelector('#copy');
const themeToggle = document.querySelector('#theme-toggle');
const themeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
const argon2Script = document.querySelector('#argon2-cdn');

function setMessage(text, isError = false) {
  message.textContent = text;
  message.classList.toggle('error', isError);
}

function resolveTheme(preference) {
  return preference === 'system' ? (themeMediaQuery.matches ? 'dark' : 'light') : preference;
}

function applyTheme(preference, persist = false) {
  const theme = resolveTheme(preference);
  document.documentElement.dataset.theme = theme;
  document.documentElement.dataset.themePreference = preference;
  const isDark = theme === 'dark';
  themeToggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  themeToggle.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  if (persist) localStorage.setItem('theme-preference', preference);
}

applyTheme(localStorage.getItem('theme-preference') || 'system');
themeToggle.addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark', true));
themeMediaQuery.addEventListener('change', () => {
  if ((localStorage.getItem('theme-preference') || 'system') === 'system') applyTheme('system');
});

togglePasswordButton.addEventListener('click', () => {
  const showing = passwordInput.type === 'text';
  passwordInput.type = showing ? 'password' : 'text';
  togglePasswordButton.textContent = showing ? 'Show' : 'Hide';
  togglePasswordButton.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
});

function markArgon2Ready() {
  if (!window.argon2) return false;
  generateButton.disabled = false;
  setMessage('Ready. Hashing runs locally in your browser.');
  return true;
}

function markArgon2Failed() {
  generateButton.disabled = true;
  setMessage('The Argon2 library could not load. Check your connection, disable blocking extensions, and reload.', true);
}

if (!markArgon2Ready()) {
  argon2Script.addEventListener('load', () => {
    if (!markArgon2Ready()) markArgon2Failed();
  }, { once: true });
  argon2Script.addEventListener('error', markArgon2Failed, { once: true });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  resultSection.hidden = true;
  hashOutput.value = '';

  const password = passwordInput.value;
  const memory = Number(memoryInput.value);
  const iterations = Number(iterationsInput.value);
  const parallelism = Number(parallelismInput.value);

  if (password.length < 12) {
    setMessage('Use a password with at least 12 characters.', true);
    return;
  }
  if (!window.argon2) {
    markArgon2Failed();
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
    setMessage('Hash generated.');
  } catch (error) {
    console.error('Argon2 hashing failed', error);
    setMessage('Hash generation failed. Try lower memory or reload the page.', true);
  } finally {
    passwordInput.value = '';
    generateButton.disabled = false;
    generateButton.textContent = 'Generate Argon2id hash';
  }
});

copyButton.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(hashOutput.value);
    copyButton.textContent = 'Copied';
    window.setTimeout(() => { copyButton.textContent = 'Copy'; }, 1800);
  } catch {
    hashOutput.focus();
    hashOutput.select();
    setMessage('Select and copy the hash manually.', true);
  }
});
