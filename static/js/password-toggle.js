/**
 * Wires a "show password" eye button to a password input. Expects the
 * button to contain two SVGs marked data-icon="eye" and data-icon="eye-off".
 */
(function (global) {
  'use strict';

  function wire(inputId, buttonId) {
    const input = document.getElementById(inputId);
    const button = document.getElementById(buttonId);
    if (!input || !button) return;

    const eyeIcon = button.querySelector('[data-icon="eye"]');
    const eyeOffIcon = button.querySelector('[data-icon="eye-off"]');

    button.addEventListener('click', function () {
      const isVisible = input.type === 'text';
      input.type = isVisible ? 'password' : 'text';
      if (eyeIcon) eyeIcon.classList.toggle('hidden', !isVisible);
      if (eyeOffIcon) eyeOffIcon.classList.toggle('hidden', isVisible);
      button.setAttribute('aria-label', isVisible ? 'Toon wachtwoord' : 'Verberg wachtwoord');
    });
  }

  global.SharitPasswordToggle = { wire: wire };
})(window);
