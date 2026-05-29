
# Security Issues

## Semgrep Findings

    static/history.js
   ❯❯❱ javascript.browser.security.insecure-document-method.insecure-document-method
          ❰❰ Blocking ❱❱
          User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` is an anti-pattern
          that can lead to XSS vulnerabilities
          Details: https://sg.run/LwA9

           50┆ p.innerHTML = p.title.replace(new RegExp(searchValue, 'gi'), match => `<span
               style="background-color: yellow;">${match}</span>`);

    static/table-quick-copy.js
   ❯❯❱ javascript.browser.security.insecure-document-method.insecure-document-method
          ❰❰ Blocking ❱❱
          User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` is an anti-pattern
          that can lead to XSS vulnerabilities
          Details: https://sg.run/LwA9

           43┆ container.innerHTML = cell.innerHTML;
            ⋮┆----------------------------------------
           92┆ button.innerHTML = originalHTML;

    static/table-row-expansion.js
   ❯❯❱ javascript.browser.security.insecure-document-method.insecure-document-method
          ❰❰ Blocking ❱❱
          User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` is an anti-pattern
          that can lead to XSS vulnerabilities
          Details: https://sg.run/LwA9

           83┆ value.innerHTML = cellClone.innerHTML;

