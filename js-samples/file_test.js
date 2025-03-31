// Testing new html elements detection 
function addElementsSequentially() {
    const elements = [
        { tag: 'iframe', attrs: { src: 'https://example.com', width: '400', height: '300' } },
        { tag: 'img', attrs: { src: 'https://via.placeholder.com/150', alt: 'Test Image' } },
        { tag: 'video', attrs: { src: 'https://www.w3schools.com/html/mov_bbb.mp4', controls: true, width: '300' } },
        { tag: 'audio', attrs: { src: 'https://www.w3schools.com/html/horse.mp3', controls: true } },
        { tag: 'embed', attrs: { src: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf', width: '300', height: '200' } }
    ];

    let index = 0;

    function addNextElement() {
        if (index < elements.length) {
            const elData = elements[index];
            const el = document.createElement(elData.tag);

            for (const [key, value] of Object.entries(elData.attrs)) {
                el.setAttribute(key, value);
            }

            document.body.appendChild(el);
            console.log(`Added <${elData.tag}> element to the page.`);

            index++;
            setTimeout(addNextElement, 1000);
        }
    }

    addNextElement();
}

addElementsSequentially();

// test cookies
document.cookie = "important_cookie=sessionId; expires=Thu, 18 Dec 2013 12:00:00 UTC; path=/; HttpOnly";
// test cookie access
document.cookie["important_cookie"]

// test sensitive cookie access
document.cookie["ASPSESSIONID"]

// test calls to dangerous methods
document.write("<img src='/test_img.png' >")
window.eval("let dangerous_declaration;")

// test localStorage
window.localStorage.getItem("a_random_key")
// test get sensitive cookie from localStorage
window.localStorage.getItem("ASPSESSIONID")