document.getElementById("back").onclick = () => {
  if (history.length > 1) history.back(); else location.href = "chrome://newtab";
};
