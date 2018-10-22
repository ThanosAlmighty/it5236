$(document).ready(function(){
  var url = window.location.pathname;
  var filename = url.substring(url.lastIndexOf('/')+1);
  $("#" + filename).css({"background-color": "#e14658", "border": "2px solid #FFFFFF","color": "#22252C";});
});
