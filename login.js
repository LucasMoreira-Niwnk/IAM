function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => toast.classList.remove("is-visible"), 2600);
}

document.querySelector("[data-login-action='ldap']").addEventListener("click", () => {
  showToast("Autenticacao LDAP sera conectada na etapa de backend.");
});
