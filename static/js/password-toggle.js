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

  /**
   * Shows a warning element while Caps Lock is on and the given password
   * input has focus. Expects the CapsLock modifier state via keyboard
   * events, so it only updates on keydown/keyup (not e.g. on programmatic
   * focus or autofill).
   */
  function watchCapsLock(inputId, warningId) {
    const input = document.getElementById(inputId);
    const warning = document.getElementById(warningId);
    if (!input || !warning) return;

    function update(event) {
      if (typeof event.getModifierState !== 'function') return;
      warning.classList.toggle('hidden', !event.getModifierState('CapsLock'));
    }

    input.addEventListener('keydown', update);
    input.addEventListener('keyup', update);
    input.addEventListener('blur', function () {
      warning.classList.add('hidden');
    });
  }

  global.SharitPasswordToggle = { wire: wire, watchCapsLock: watchCapsLock };
})(window);
