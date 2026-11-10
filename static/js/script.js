// Mobile navigation toggle


/* ===== Modern dropdowns (same look and behaviour as the register page) =====
   Turns every <select> on a page into the styled menu, except the ones inside the
   register form (which already set up their own) and any <select data-native>. */
(function () {
  'use strict';

  function buildModernSelect(selectEl) {
    selectEl.classList.add('visually-hidden');
    selectEl.tabIndex = -1;
    selectEl.setAttribute('aria-hidden', 'true');

    const container = document.createElement('div');
    container.className = 'custom-select-container';

    const trigger = document.createElement('div');
    trigger.className = 'custom-select-trigger';
    trigger.tabIndex = selectEl.disabled ? -1 : 0;
    trigger.setAttribute('role', 'button');
    trigger.setAttribute('aria-haspopup', 'listbox');
    if (selectEl.disabled) trigger.classList.add('disabled');

    const triggerText = document.createElement('span');
    triggerText.textContent = selectEl.options[selectEl.selectedIndex]?.text || 'Select';
    const arrow = document.createElement('div');
    arrow.className = 'custom-select-arrow';
    trigger.appendChild(triggerText);
    trigger.appendChild(arrow);
    container.appendChild(trigger);

    const optionsList = document.createElement('ul');
    optionsList.className = 'custom-select-options';
    optionsList.setAttribute('role', 'listbox');
    container.appendChild(optionsList);
    selectEl.parentNode.insertBefore(container, selectEl.nextSibling);

    function rebuildOptions() {
      optionsList.innerHTML = '';
      Array.from(selectEl.options).forEach((opt) => {
        if (!opt.value) return;
        const li = document.createElement('li');
        li.className = 'custom-option';
        li.setAttribute('role', 'option');
        li.textContent = opt.textContent;
        li.dataset.value = opt.value;
        if (selectEl.value === opt.value) li.classList.add('selected');
        li.addEventListener('click', function (e) {
          e.stopPropagation();
          selectEl.value = this.dataset.value;
          triggerText.textContent = this.textContent;
          optionsList.querySelectorAll('.custom-option').forEach((el) => el.classList.remove('selected'));
          this.classList.add('selected');
          container.classList.remove('open');
          selectEl.dispatchEvent(new Event('change', { bubbles: true }));
        });
        optionsList.appendChild(li);
      });
    }
    rebuildOptions();

    function toggle() {
      if (selectEl.disabled) return;
      document.querySelectorAll('.custom-select-container').forEach((c) => {
        if (c !== container) c.classList.remove('open');
      });
      container.classList.toggle('open');
      trigger.setAttribute('aria-expanded', container.classList.contains('open') ? 'true' : 'false');
    }

    trigger.addEventListener('click', function (e) {
      e.stopPropagation();
      toggle();
    });
    trigger.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
      if (e.key === 'Escape') container.classList.remove('open');
    });
  }

  function initModernSelects() {
    document.querySelectorAll('select').forEach((sel) => {
      if (sel.closest('.register-form') || sel.hasAttribute('data-native')) return;
      if (sel.dataset.modern === 'done') return;
      sel.dataset.modern = 'done';
      buildModernSelect(sel);
    });
    document.addEventListener('click', function () {
      document.querySelectorAll('.custom-select-container.open').forEach((c) => c.classList.remove('open'));
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initModernSelects);
  } else {
    initModernSelects();
  }
})();
