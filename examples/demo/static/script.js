function getCookie(name) {
  var cookieArr = document.cookie.split(";");
 
  for(var i = 0; i < cookieArr.length; i++) {
    var cookiePair = cookieArr[i].split("=");
    if(name == cookiePair[0].trim()) {
      return decodeURIComponent(cookiePair[1]);
    }
  }
 
  return undefined;
}

function setCookie(name, value, expirationDays) {
  var date = new Date();
  date.setTime(date.getTime() + (expirationDays * 24 * 60 * 60 * 1000));
  var expires = "expires=" + date.toUTCString();
  document.cookie = name + "=" + encodeURIComponent(value) + ";" + expires + ";path=/";
}

var init = document.getElementById("init")

window.addEventListener("DOMContentLoaded", function() {
  popup = getCookie("popup") || 0;
  if (popup != 1) {
    window.location.replace("#init")
    setCookie("popup", 1, 1)
  }
})