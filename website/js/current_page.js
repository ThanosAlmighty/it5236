$(document).ready(function(){
  var url = window.location.pathname;
  var filename = url.substring(url.lastIndexOf('/')+1);
alert(filename);
    $("#" + filename).attr("class","current");
});
