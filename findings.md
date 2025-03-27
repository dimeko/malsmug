### Findings on mal js scripts


#### file1.js

- It makes a call to a suspicious IP
- `document.write( "<script src ="+url+"></script>");` is always suspicious. It writes a new script to the DOM


#### file2.js




#### file3.js




#### file4.js





