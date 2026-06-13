/* WhiteMoon — Auditoría GEO IA · frontend */

(function () {
  "use strict";

  // Disponible en todas las páginas (index y listado de informes)
  window.exportPdf = function (filename, btn) {
    if (btn) btn.disabled = true;
    fetch("/export-pdf/" + encodeURIComponent(filename), { method: "POST" })
      .then(function (r) {
        var ct = r.headers.get("Content-Type") || "";
        if (ct.indexOf("application/pdf") !== -1) {
          return r.blob().then(function (blob) {
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = filename.replace(/\.md$/, ".pdf");
            a.click();
            URL.revokeObjectURL(a.href);
          });
        }
        return r.json().then(function (j) {
          if (j.fallback === "print" && j.url) {
            // Sin weasyprint en el servidor → impresión del navegador
            window.open(j.url, "_blank");
          } else {
            alert(j.error || "No se pudo generar el PDF");
          }
        });
      })
      .catch(function (e) { alert("Error generando PDF: " + e.message); })
      .then(function () { if (btn) btn.disabled = false; });
  };

  var form = document.getElementById("audit-form");
  if (!form) return; // página sin formulario

  var $ = function (id) { return document.getElementById(id); };

  var loading = $("loading");
  var loadingMsg = $("loading-msg");
  var errorBox = $("error-box");
  var result = $("result");
  var btnAudit = $("btn-audit");
  var sectorSel = $("f-sector");
  var sectorOtro = $("f-sector-otro");

  var lastAudit = null; // respuesta completa de /audit

  var LOADING_MSGS = [
    "Descargando web del cliente...",
    "Analizando SEO técnico...",
    "Verificando señales GEO...",
    "Comprobando AEO...",
    "Generando informe..."
  ];
  var loadingTimer = null;
  var wakeTimer = null;

  // Plan gratuito de Render: el servidor puede tardar ~50s en despertar
  var AUDIT_TIMEOUT_MS = 120000;
  var WAKE_MSG = "El servidor está despertando, puede tardar hasta 60 segundos la primera vez...";

  var NIVEL_COLOR = {
    "Crítico": "#ff4d6d",
    "Mejorable": "#f5c842",
    "Bueno": "#00d4aa",
    "Excelente": "#7c4dff"
  };

  // ── Sector "otro" → campo libre ──
  sectorSel.addEventListener("change", function () {
    sectorOtro.hidden = sectorSel.value !== "otro";
    if (!sectorOtro.hidden) sectorOtro.focus();
  });

  // ── Validación ──
  function validate() {
    var ok = true;
    var url = $("f-url").value.trim();
    var urlRe = /^(https?:\/\/)?[a-z0-9¡-ﻼ]([a-z0-9¡-ﻼ.-]*)\.[a-z]{2,}([\/?#].*)?$/i;
    setErr("url", "");
    setErr("nombre", "");
    setErr("ciudad", "");
    setErr("sector", "");

    if (!url || (!urlRe.test(url) && url.indexOf("localhost") === -1)) {
      setErr("url", "Introduce una URL válida, ej: https://cliente.es");
      ok = false;
    }
    if (!$("f-nombre").value.trim()) { setErr("nombre", "Obligatorio"); ok = false; }
    if (!$("f-ciudad").value.trim()) { setErr("ciudad", "Obligatorio"); ok = false; }
    if (sectorSel.value === "otro" && !sectorOtro.value.trim()) {
      setErr("sector", "Escribe el sector"); ok = false;
    }
    return ok;
  }

  function setErr(field, msg) {
    var el = $("err-" + field);
    if (el) el.textContent = msg;
    var input = $("f-" + field);
    if (input) input.classList.toggle("invalid", !!msg);
  }

  // ── Loading con mensajes rotatorios ──
  function startLoading() {
    var i = 0;
    loadingMsg.textContent = LOADING_MSGS[0];
    loading.hidden = false;
    errorBox.hidden = true;
    result.hidden = true;
    btnAudit.disabled = true;
    loadingTimer = setInterval(function () {
      i = Math.min(i + 1, LOADING_MSGS.length - 1);
      loadingMsg.style.opacity = 0;
      setTimeout(function () {
        loadingMsg.textContent = LOADING_MSGS[i];
        loadingMsg.style.opacity = 1;
      }, 250);
    }, 1700);
    // Más de 10s sin respuesta → probablemente cold start de Render
    wakeTimer = setTimeout(function () {
      clearInterval(loadingTimer);
      loadingMsg.style.opacity = 0;
      setTimeout(function () {
        loadingMsg.textContent = WAKE_MSG;
        loadingMsg.style.opacity = 1;
      }, 250);
    }, 10000);
  }

  function stopLoading() {
    clearInterval(loadingTimer);
    clearTimeout(wakeTimer);
    loading.hidden = true;
    btnAudit.disabled = false;
  }

  // ── Submit ──
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!validate()) return;

    var payload = {
      url: $("f-url").value.trim(),
      nombre: $("f-nombre").value.trim(),
      sector: sectorSel.value === "otro" ? sectorOtro.value.trim() : sectorSel.value,
      ciudad: $("f-ciudad").value.trim(),
      html: $("f-html").value.trim()
    };

    startLoading();

    // Timeout de 120s vía AbortController (fetch no tiene timeout nativo)
    var controller = new AbortController();
    var abortTimer = setTimeout(function () { controller.abort(); }, AUDIT_TIMEOUT_MS);

    fetch("/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (res) {
        clearTimeout(abortTimer);
        stopLoading();
        if (!res.body.ok) {
          showError(res.body.error || "Error desconocido (HTTP " + res.status + ")");
          return;
        }
        lastAudit = res.body;
        renderResult(res.body);
      })
      .catch(function (err) {
        clearTimeout(abortTimer);
        stopLoading();
        if (err.name === "AbortError") {
          showError("La auditoría ha tardado más de 120 segundos y se ha cancelado. " +
                    "Vuelve a intentarlo en un momento.");
        } else if (/failed to fetch|networkerror|load failed/i.test(err.message || "")) {
          showError("El servidor está iniciando. Espera 30 segundos y vuelve a intentarlo.");
        } else {
          showError("No se pudo conectar con el servidor: " + err.message);
        }
      });
  });

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
  }

  // ── Render del resultado ──
  function renderResult(d) {
    result.hidden = false;
    var color = NIVEL_COLOR[d.nivel] || "#7c4dff";

    // Gauge semicircular (longitud del arco r=86 → π·86)
    var fill = $("gauge-fill");
    var len = Math.PI * 86;
    fill.style.strokeDasharray = len;
    fill.style.strokeDashoffset = len; // reset
    fill.style.stroke = color;
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        fill.style.strokeDashoffset = len * (1 - d.score / 100);
      });
    });

    // Contador 0 → score en 1.5s
    animateCounter($("score-counter"), d.score, 1500);

    // Pill de nivel
    var pill = $("nivel-pill");
    pill.textContent = d.nivel + " — " + d.nivel_desc;
    pill.style.color = color;
    pill.style.borderColor = color;
    pill.style.background = hexToRgba(color, 0.1);

    $("frase").textContent = d.frase;

    // Dos métricas: Score Técnico y Score Control IA
    $("sc-tecnico").textContent = trimNum(d.tecnico) + "/" + trimNum(d.tecnico_max);
    $("sc-control").textContent = trimNum(d.control) + "/" + trimNum(d.control_max);

    // Barras
    setBar("seo", d.seo, d.seo_max);
    setBar("geo", d.geo, d.geo_max);
    setBar("aeo", d.aeo, d.aeo_max);

    // Botones
    $("btn-ver").href = "/reports/" + encodeURIComponent(d.filename);

    // Problemas urgentes
    fillList("problemas", "problemas-wrap", d.problemas, function (p) {
      var li = document.createElement("li");
      li.textContent = p;
      return li;
    });

    // Errores / warnings
    fillIssues("errores", "errores-wrap", "err-count", "toggle-err", d.errores_criticos, "err", "ERROR");
    fillIssues("warnings", "warnings-wrap", "warn-count", "toggle-warn", d.warnings, "warn", "WARNING");

    result.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function setBar(area, pts, max) {
    var el = $("bar-" + area);
    el.style.width = "0%";
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        el.style.width = (max ? (pts / max) * 100 : 0) + "%";
      });
    });
    $("pts-" + area).textContent = trimNum(pts) + "/" + trimNum(max);
  }

  function fillList(listId, wrapId, items, makeLi) {
    var ul = $(listId);
    ul.innerHTML = "";
    (items || []).forEach(function (it) { ul.appendChild(makeLi(it)); });
    $(wrapId).hidden = !items || !items.length;
  }

  var ISSUE_LIMIT = 6;

  function fillIssues(listId, wrapId, countId, toggleId, items, tagClass, tagText) {
    items = items || [];
    $(countId).textContent = items.length;
    var ul = $(listId);
    ul.innerHTML = "";
    items.forEach(function (it, i) {
      var li = document.createElement("li");
      if (i >= ISSUE_LIMIT) li.hidden = true;

      var tag = document.createElement("span");
      tag.className = "tag " + tagClass;
      tag.textContent = tagText;
      li.appendChild(tag);

      var span = document.createElement("span");
      span.textContent = it.check;
      li.appendChild(span);

      if (it.detail) {
        var det = document.createElement("span");
        det.className = "detail";
        det.textContent = "— " + it.detail;
        li.appendChild(det);
      }
      ul.appendChild(li);
    });
    $(wrapId).hidden = !items.length;

    var toggle = $(toggleId);
    if (items.length > ISSUE_LIMIT) {
      toggle.hidden = false;
      toggle.dataset.open = "0";
      toggle.textContent = "Mostrar " + (items.length - ISSUE_LIMIT) + " más";
      toggle.onclick = function () {
        var open = toggle.dataset.open === "1";
        Array.prototype.forEach.call(ul.children, function (li, i) {
          if (i >= ISSUE_LIMIT) li.hidden = open;
        });
        toggle.dataset.open = open ? "0" : "1";
        toggle.textContent = open ? "Mostrar " + (items.length - ISSUE_LIMIT) + " más" : "Mostrar menos";
      };
    } else {
      toggle.hidden = true;
    }
  }

  function animateCounter(el, target, duration) {
    var start = performance.now();
    function tick(now) {
      var t = Math.min((now - start) / duration, 1);
      var eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
      el.textContent = Math.round(eased * target);
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function trimNum(n) {
    return (Math.round(n * 10) / 10).toString().replace(/\.0$/, "");
  }

  function hexToRgba(hex, a) {
    var n = parseInt(hex.slice(1), 16);
    return "rgba(" + (n >> 16) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
  }

  // ── Botones del resultado ──
  $("btn-copy").addEventListener("click", function () {
    if (!lastAudit) return;
    navigator.clipboard.writeText(lastAudit.informe_md).then(function () {
      flashBtn($("btn-copy"), "Copiado");
    }, function () {
      flashBtn($("btn-copy"), "Error al copiar");
    });
  });

  $("btn-pdf").addEventListener("click", function () {
    if (!lastAudit) return;
    exportPdf(lastAudit.filename, $("btn-pdf"));
  });

  function flashBtn(btn, text) {
    var orig = btn.textContent;
    btn.textContent = text;
    setTimeout(function () { btn.textContent = orig; }, 1800);
  }

})();
