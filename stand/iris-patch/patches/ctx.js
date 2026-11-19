try {
  var m = location.pathname.match(/^\/case\/(\d+)/);
  if (m) {
    var key = 'iris_app_context';
    var ctx = {};
    try { ctx = JSON.parse(localStorage.getItem(key) || '{}'); } catch (e) { ctx = {}; }
    if (String(ctx.currentCaseID) !== m[1]) {
      ctx.currentCaseID = Number(m[1]);
      localStorage.setItem(key, JSON.stringify(ctx));
    }
  }
} catch (e) {}
