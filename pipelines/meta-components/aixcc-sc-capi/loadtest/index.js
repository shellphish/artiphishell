// File imported from k6's website so that k6 can run offline

var nr = Object.create;
var z = Object.defineProperty;
var ar = Object.getOwnPropertyDescriptor;
var tr = Object.getOwnPropertyNames;
var sr = Object.getPrototypeOf,
  ur = Object.prototype.hasOwnProperty;
var H = (r, e) => () => (e || r((e = { exports: {} }).exports, e), e.exports),
  ir = (r, e) => {
    for (var n in e) z(r, n, { get: e[n], enumerable: !0 });
  },
  J = (r, e, n, t) => {
    if ((e && typeof e == "object") || typeof e == "function")
      for (let a of tr(e))
        !ur.call(r, a) &&
          a !== n &&
          z(r, a, {
            get: () => e[a],
            enumerable: !(t = ar(e, a)) || t.enumerable,
          });
    return r;
  };
var K = (r, e, n) => (
    (n = r != null ? nr(sr(r)) : {}),
    J(
      e || !r || !r.__esModule
        ? z(n, "default", { value: r, enumerable: !0 })
        : n,
      r,
    )
  ),
  lr = (r) => J(z({}, "__esModule", { value: !0 }), r);
var Y = H((X) => {
  var fr = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  };
  function S(r) {
    return r.replace(/[&<>'"]/g, (e) => fr[e]);
  }
  function or(r, e) {
    let n = e && e.name ? S(e.name) : "k6 thresholds",
      t = e && e.classname ? S(e.classname) : "Unnamed folder",
      a = 0,
      s = [];
    return (
      Object.entries(r.metrics).forEach(([M, p]) => {
        !p.thresholds ||
          Object.entries(p.thresholds).forEach(([g, w]) => {
            let T = `${S(M)} - ${S(g)}`;
            if (w.ok) s.push(`<testcase name="${T}" classname="${t}" />`);
            else {
              a++;
              let b =
                `${p.type} threshold failed: ` +
                Object.entries(p.values)
                  .map(([$, O]) => `${$} value: ${O}`)
                  .join(", ");
              s.push(
                `<testcase name="${T}" classname="${t}"><failure message="${S(b)}" /></testcase>`,
              );
            }
          });
      }),
      `<?xml version="1.0"?>
    <testsuites tests="${s.length}" failures="${a}">
      <testsuite name="${n}" tests="${s.length}" failures="${a}">
        ${s.join(`
`)}
      </testsuite>
    </testsuites>`
    );
  }
  X.jUnit = or;
});
var U = H((N) => {
  var _ = function (r, e) {
      for (var n in r)
        if (Object.prototype.hasOwnProperty.call(r, n) && e(n, r[n])) break;
    },
    c = { bold: 1, faint: 2, red: 31, green: 32, cyan: 36 },
    vr = "\u2588",
    hr = "\u21B3",
    A = "\u2713",
    C = "\u2717",
    cr = {
      indent: " ",
      enableColors: !0,
      summaryTimeUnit: null,
      summaryTrendStats: null,
    };
  function m(r) {
    var e = r.normalize("NFKC"),
      n = !1,
      t = !1,
      a = 0;
    for (var s of e) {
      if (s.done) break;
      if (s == "\x1B") {
        n = !0;
        continue;
      }
      if (n && s == "[") {
        t = !0;
        continue;
      }
      if (n && t && s.charCodeAt(0) >= 64 && s.charCodeAt(0) <= 126) {
        (n = !1), (t = !1);
        continue;
      }
      if (n && !t && s.charCodeAt(0) >= 64 && s.charCodeAt(0) <= 95) {
        n = !1;
        continue;
      }
      !n && !t && a++;
    }
    return a;
  }
  function pr(r, e, n) {
    if (e.fails == 0) return n(r + A + " " + e.name, c.green);
    var t = Math.floor((100 * e.passes) / (e.passes + e.fails));
    return n(
      r +
        C +
        " " +
        e.name +
        `
` +
        r +
        " " +
        hr +
        "  " +
        t +
        "% \u2014 " +
        A +
        " " +
        e.passes +
        " / " +
        C +
        " " +
        e.fails,
      c.red,
    );
  }
  function k(r, e, n) {
    var t = [];
    e.name != "" &&
      (t.push(
        r +
          vr +
          " " +
          e.name +
          `
`,
      ),
      (r = r + "  "));
    for (let a = 0; a < e.checks.length; a++) t.push(pr(r, e.checks[a], n));
    e.checks.length > 0 && t.push("");
    for (let a = 0; a < e.groups.length; a++)
      Array.prototype.push.apply(t, k(r, e.groups[a], n));
    return t;
  }
  function Q(r) {
    var e = r.indexOf("{");
    return e >= 0 ? "{ " + r.substring(e + 1, r.length - 1) + " }" : r;
  }
  function R(r) {
    return r.indexOf("{") >= 0 ? "  " : "";
  }
  function gr(r) {
    var e = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"],
      n = 1e3;
    if (r < 10) return r + " B";
    var t = Math.floor(Math.log(r) / Math.log(n)),
      a = e[t | 0],
      s = Math.floor((r / Math.pow(n, t)) * 10 + 0.5) / 10;
    return s.toFixed(s < 10 ? 1 : 0) + " " + a;
  }
  var V = {
    s: { unit: "s", coef: 0.001 },
    ms: { unit: "ms", coef: 1 },
    us: { unit: "\xB5s", coef: 1e3 },
  };
  function I(r, e) {
    return parseFloat(r.toFixed(e)).toString();
  }
  function D(r, e) {
    var n = Math.pow(10, e);
    return I(Math.trunc(n * r) / n, e);
  }
  function yr(r) {
    if (r === 0) return "0s";
    if (r < 0.001) return Math.trunc(r * 1e6) + "ns";
    if (r < 1) return D(r * 1e3, 2) + "\xB5s";
    if (r < 1e3) return D(r, 2) + "ms";
    var e = D((r % 6e4) / 1e3, r > 6e4 ? 0 : 2) + "s",
      n = Math.trunc(r / 6e4);
    return n < 1 || ((e = (n % 60) + "m" + e), (n = Math.trunc(n / 60)), n < 1)
      ? e
      : n + "h" + e;
  }
  function mr(r, e) {
    return e !== "" && Object.prototype.hasOwnProperty.call(V, e)
      ? (r * V[e].coef).toFixed(2) + V[e].unit
      : yr(r);
  }
  function d(r, e, n) {
    if (e.type == "rate")
      return (Math.trunc(r * 100 * 100) / 100).toFixed(2) + "%";
    switch (e.contains) {
      case "data":
        return gr(r);
      case "time":
        return mr(r, n);
      default:
        return I(r, 6);
    }
  }
  function xr(r, e) {
    switch (r.type) {
      case "counter":
        return [d(r.values.count, r, e), d(r.values.rate, r, e) + "/s"];
      case "gauge":
        return [
          d(r.values.value, r, e),
          "min=" + d(r.values.min, r, e),
          "max=" + d(r.values.max, r, e),
        ];
      case "rate":
        return [
          d(r.values.rate, r, e),
          A + " " + r.values.passes,
          C + " " + r.values.fails,
        ];
      default:
        return ["[no data]"];
    }
  }
  function dr(r, e, n) {
    var t = r.indent + "  ",
      a = [],
      s = [],
      M = 0,
      p = {},
      g = 0,
      w = {},
      T = [0, 0],
      b = {},
      $ = r.summaryTrendStats.length,
      O = new Array($).fill(0);
    _(e.metrics, function (u, l) {
      s.push(u);
      var y = R(u) + Q(u),
        x = m(y);
      if ((x > M && (M = x), l.type == "trend")) {
        var v = [];
        for (let o = 0; o < $; o++) {
          var f = r.summaryTrendStats[o],
            h = l.values[f];
          f === "count" ? (h = h.toString()) : (h = d(h, l, r.summaryTimeUnit));
          var i = m(h);
          i > O[o] && (O[o] = i), (v[o] = h);
        }
        b[u] = v;
        return;
      }
      var j = xr(l, r.summaryTimeUnit);
      p[u] = j[0];
      var Z = m(j[0]);
      Z > g && (g = Z), (w[u] = j.slice(1));
      for (let o = 1; o < j.length; o++) {
        var W = m(j[o]);
        W > T[o - 1] && (T[o - 1] = W);
      }
    }),
      s.sort(function (u, l) {
        var y = u.split("{", 1)[0],
          x = l.split("{", 1)[0],
          v = y.localeCompare(x);
        if (v !== 0) return v;
        var f = u.substring(y.length),
          h = l.substring(x.length);
        return f.localeCompare(h);
      });
    var er = function (u) {
      if (Object.prototype.hasOwnProperty.call(b, u)) {
        var l = b[u],
          y = new Array($);
        for (let i = 0; i < l.length; i++)
          y[i] =
            r.summaryTrendStats[i] +
            "=" +
            n(l[i], c.cyan) +
            " ".repeat(O[i] - m(l[i]));
        return y.join(" ");
      }
      var x = p[u],
        v = n(x, c.cyan) + " ".repeat(g - m(x)),
        f = w[u];
      if (f.length == 1) v = v + " " + n(f[0], c.cyan, c.faint);
      else if (f.length > 1) {
        var h = new Array(f.length);
        for (let i = 0; i < f.length; i++)
          h[i] = n(f[i], c.cyan, c.faint) + " ".repeat(T[i] - m(f[i]));
        v = v + " " + h.join(" ");
      }
      return v;
    };
    for (var B of s) {
      var q = e.metrics[B],
        P = " ",
        L = function (u) {
          return u;
        };
      q.thresholds &&
        ((P = A),
        (L = function (u) {
          return n(u, c.green);
        }),
        _(q.thresholds, function (u, l) {
          if (!l.ok)
            return (
              (P = C),
              (L = function (y) {
                return n(y, c.red);
              }),
              !0
            );
        }));
      var G = R(B),
        F = Q(B);
      (F = F + n(".".repeat(M - m(F) - m(G) + 3) + ":", c.faint)),
        a.push(t + G + L(P) + " " + F + " " + er(B));
    }
    return a;
  }
  function Mr(r, e) {
    var n = Object.assign({}, cr, r.options, e),
      t = [],
      a = function (s) {
        return s;
      };
    return (
      n.enableColors &&
        (a = function (s, M) {
          for (var p = "\x1B[" + M, g = 2; g < arguments.length; g++)
            p += ";" + arguments[g];
          return p + "m" + s + "\x1B[0m";
        }),
      Array.prototype.push.apply(t, k(n.indent + "    ", r.root_group, a)),
      Array.prototype.push.apply(t, dr(n, r, a)),
      t.join(`
`)
    );
  }
  N.humanizeValue = d;
  N.textSummary = Mr;
});
var Tr = {};
ir(Tr, {
  humanizeValue: () => E.humanizeValue,
  jUnit: () => rr.jUnit,
  textSummary: () => E.textSummary,
});
module.exports = lr(Tr);
var rr = K(Y()),
  E = K(U());
