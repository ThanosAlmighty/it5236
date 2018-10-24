$(document).ready(function(){
  var url = window.location.pathname;
  var filename = url.substring(url.lastIndexOf('/')+1);
  filename = filename.slice(0, -4);
  console.log(filename);
  $("#" + filename).css({"background-color": "#e14658", "border": "2px solid #FFFFFF","color": "#22252C"});
});
