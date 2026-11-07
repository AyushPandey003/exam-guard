// Pure local typing metrics; no network requests or typed-text storage.
(function (root) {
  const passage = 'Careful typing is more useful than rushing. Keep a natural rhythm, read each word, and correct mistakes as you go.';

  function metrics(text, expected, elapsedMs) {
    const typed = Array.from(text);
    const target = Array.from(expected);
    const correct = typed.reduce((n, char, i) => n + (char === target[i] ? 1 : 0), 0);
    return {
      characters: typed.length,
      wpm: elapsedMs > 0 ? Math.round((typed.length / 5) / (elapsedMs / 60000)) : 0,
      accuracy: typed.length ? Math.round(correct / typed.length * 100) : 100,
      seconds: Math.floor(Math.max(0, elapsedMs) / 1000),
    };
  }

  function diagnosticSummary(d) {
    if (!d.supported) return 'Native input monitoring is not supported on this platform. Typing practice still works.';
    if (!d.keyboard_active || !d.mouse_active) return 'Input hooks are not both active. Start the system check; if this persists, monitoring is incomplete.';
    const flags = [];
    if (d.injected_keys >= 3 || d.injected_clicks >= 3) flags.push('INJECTED_INPUT threshold reached');
    if (d.samples >= 40 && d.mean_ms !== null && d.sd_ms !== null && d.mean_ms < 250 && d.sd_ms < 4) {
      flags.push('INPUT_TIMING threshold reached');
    }
    if (flags.length) return flags.join(' · ') + '. These are heuristics, not proof of cheating.';
    return d.samples < 40 ? 'Collecting timing samples (40 required). No input threshold reached.' : 'No input threshold reached.';
  }

  const api = { passage, metrics, diagnosticSummary };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.TypingTest = api;
})(typeof window !== 'undefined' ? window : globalThis);
