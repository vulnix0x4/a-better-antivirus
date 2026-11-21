// Small conveniences only. The page works in full without this file.
//  1. Notice the visitor's operating system and say so if it isn't Windows.
//  2. Add "Copy" buttons to the commands.
// Nothing here sends or stores anything.
(function () {
  'use strict';

  function detectOS() {
    var nav = window.navigator || {};
    var ua = nav.userAgent || '';
    var platform = (nav.userAgentData && nav.userAgentData.platform) || nav.platform || '';
    var s = platform + ' ' + ua;

    if (/Android/i.test(s)) return 'mobile';
    if (/iPhone|iPad|iPod/i.test(s)) return 'mobile';
    // iPadOS says it is a Mac; a Mac has no touch screen.
    if (/Mac/i.test(platform) && nav.maxTouchPoints > 1) return 'mobile';
    if (/Windows Phone/i.test(s)) return 'mobile';
    if (/Win/i.test(platform) || /Windows/i.test(ua)) {
      // Windows 10 and 11 both report "Windows NT 10.0". Anything lower is too old.
      var m = /Windows NT (\d+)\.(\d+)/.exec(ua);
      if (m && parseInt(m[1], 10) < 10) return 'windows-old';
      return 'windows';
    }
    if (/Mac/i.test(s)) return 'macos';
    if (/CrOS/i.test(s)) return 'other';
    if (/Linux|X11/i.test(s)) return 'linux';
    return '';
  }

  var os = detectOS();
  if (os) {
    document.documentElement.setAttribute('data-os', os);

    // Notes written in the HTML, one per system; show the one that fits.
    var notes = document.querySelectorAll('[data-os-note]');
    for (var i = 0; i < notes.length; i++) {
      var want = notes[i].getAttribute('data-os-note');
      var show = want === os || (want === 'not-windows' && os !== 'windows' && os !== 'windows-old');
      if (show) notes[i].hidden = false;
    }

    // Mark the visitor's own system in the download list.
    var mine = document.querySelector('.platform[data-os="' + os + '"] .platform-yours');
    if (mine) mine.hidden = false;
  }

  // Copy buttons. They stay hidden where the browser can't copy.
  if (window.navigator.clipboard && window.navigator.clipboard.writeText) {
    var buttons = document.querySelectorAll('button[data-copy]');
    Array.prototype.forEach.call(buttons, function (button) {
      var source = document.getElementById(button.getAttribute('data-copy'));
      if (!source) return;
      var label = button.textContent;
      var timer = null;
      button.hidden = false;
      button.addEventListener('click', function () {
        window.navigator.clipboard.writeText(source.textContent.trim()).then(function () {
          button.textContent = 'Copied';
        }, function () {
          button.textContent = 'Could not copy';
        }).then(function () {
          window.clearTimeout(timer);
          timer = window.setTimeout(function () { button.textContent = label; }, 2000);
        });
      });
    });
  }
})();
