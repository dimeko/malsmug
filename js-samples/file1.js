var par=document.scripts[document.scripts.length-2].text;
par = par.replace('<!--', '');
par = par.replace('-->', '');
par = par.split("-");
var i = par[0];
var o = par[1];
var u = par[2];
function zdRndNum(n){
    var rnd="";
    for(var i=0;i<n;i++)
        rnd+=Math.floor(Math.random()*10);
    return rnd;
}
function isIE() {
    if (!!window.ActiveXObject || "ActiveXObject" in window)
        return true;
    else
        return false;
}
var zdrandomnum = zdRndNum(10);
if(u){
    var url = "//sspapi.zenyou.71360.com/js?i="+i+"&o="+o+"&u="+u+"&ran="+zdrandomnum;
}else{
    var url = "//sspapi.zenyou.71360.com/js?i="+i+"&o="+o+"&ran="+zdrandomnum;
}
var isie = isIE();
if (isie)  {
    document.write( "<script src ="+url+"></script>");
}else{
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url, false);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.onreadystatechange = function () {
        var XMLHttpReq = xhr;
        if (XMLHttpReq.readyState == 4) {
            if (XMLHttpReq.status == 200) {
                var text = XMLHttpReq.responseText;
                if(window.execScript) {
                    window.execScript(text);
                } else {
                    window.eval(text);
                }
            }
        }
    };
    xhr.send(null);
}
