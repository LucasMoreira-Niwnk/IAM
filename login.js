function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => toast.classList.remove("is-visible"), 2600);
}

const API_BASE_URL = window.IAM_API_BASE_URL || localStorage.getItem("IAM_API_BASE_URL") || "";

async function loginWithLdap(username, password) {
  const response = await fetch(`${API_BASE_URL}/api/auth/ldap/login`, {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    throw new Error("Usuário ou senha inválidos, ou usuário fora do grupo de operadores.");
  }

  return response.json();
}

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const submitButton = form.querySelector("[type='submit']");
  const username = form.elements.username.value.trim();
  const password = form.elements.password.value;

  if (!username || !password) {
    showToast("Informe usuário e senha do AD.");
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = "Entrando...";

  try {
    await loginWithLdap(username, password);
    window.location.href = "/inicio/";
  } catch (error) {
    showToast(error.message);
    form.elements.password.value = "";
    form.elements.password.focus();
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Entrar";
  }
});

const logoutReason = sessionStorage.getItem("IAM_LOGOUT_REASON");
if (logoutReason) {
  showToast(logoutReason);
  sessionStorage.removeItem("IAM_LOGOUT_REASON");
}
