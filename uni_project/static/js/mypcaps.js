document.querySelectorAll('#menu li').forEach(item => {
    item.addEventListener('click', function () {
      const page = this.getAttribute('data-page');
      fetch(page).then(response => {
        if (!response.ok) {
          document.getElementById('content').innerHTML = '<h2>Page Not Available</h2>';
        } else {
          return response.text();
        }
      }).then(html => {
        if (html) {
          document.getElementById('content').innerHTML = html;
        }
      }).catch(() => {
        document.getElementById('content').innerHTML = '<h2>Page Not Available</h2>';
      });
    });
  });