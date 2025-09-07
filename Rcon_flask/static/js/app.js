// reserved for future animations or websocket hooks for realtime streaming
// subtle pulse on hover (neon glow intensity)
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.step-card, .btn-primary, .btn-secondary, .card').forEach(el => {
    el.addEventListener('mouseenter', () => el.classList.add('shadow-neonStrong'));
    el.addEventListener('mouseleave', () => el.classList.remove('shadow-neonStrong'));
  });
});
