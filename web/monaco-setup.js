/**
 * APK Security Studio — Monaco Editor Setup
 * Configures Monaco with smali syntax highlighting and custom features.
 */

// ─── Monaco Loader ────────────────────────────────────────────────────────────
window.monacoReady = false;
window.monacoReadyCallbacks = [];

require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' } });

require(['vs/editor/editor.main'], function() {
  // ── Smali Language Definition ────────────────────────────────────────────────
  monaco.languages.register({ id: 'smali' });

  monaco.languages.setMonarchTokensProvider('smali', {
    keywords: [
      '.class', '.super', '.implements', '.field', '.method', '.end', '.registers',
      '.prologue', '.epilogue', '.line', '.source', '.annotation', '.param',
      '.local', '.restart', '.catch', '.catchall', '.packed-switch', '.sparse-switch',
      '.array-data', '.end method', '.end annotation', '.end field', 'public', 'private',
      'protected', 'static', 'final', 'abstract', 'synthetic', 'constructor',
      'interface', 'enum', 'bridge', 'varargs', 'native', 'transient', 'volatile',
      'synchronized', 'declared-synchronized'
    ],
    opcodes: [
      'nop', 'move', 'move-wide', 'move-object', 'move-result', 'move-result-wide',
      'move-result-object', 'move-exception', 'return-void', 'return', 'return-wide',
      'return-object', 'const', 'const-wide', 'const-string', 'const-class',
      'monitor-enter', 'monitor-exit', 'check-cast', 'instance-of', 'array-length',
      'new-instance', 'new-array', 'filled-new-array', 'fill-array-data',
      'throw', 'goto', 'packed-switch', 'sparse-switch', 'if-eq', 'if-ne',
      'if-lt', 'if-ge', 'if-gt', 'if-le', 'if-eqz', 'if-nez', 'if-ltz',
      'if-gez', 'if-gtz', 'if-lez', 'aget', 'aget-wide', 'aget-object',
      'aget-boolean', 'aget-byte', 'aget-char', 'aget-short', 'aput', 'aput-wide',
      'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short',
      'iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char',
      'iget-short', 'iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte',
      'iput-char', 'iput-short', 'sget', 'sget-wide', 'sget-object', 'sget-boolean',
      'sget-byte', 'sget-char', 'sget-short', 'sput', 'sput-wide', 'sput-object',
      'sput-boolean', 'sput-byte', 'sput-char', 'sput-short', 'invoke-virtual',
      'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface',
      'invoke-virtual-range', 'invoke-super-range', 'invoke-direct-range',
      'invoke-static-range', 'invoke-interface-range', 'neg-int', 'not-int',
      'neg-long', 'not-long', 'neg-float', 'neg-double', 'int-to-long',
      'int-to-float', 'int-to-double', 'long-to-int', 'long-to-float',
      'long-to-double', 'float-to-int', 'float-to-long', 'float-to-double',
      'double-to-int', 'double-to-long', 'double-to-float', 'int-to-byte',
      'int-to-char', 'int-to-short', 'add-int', 'sub-int', 'mul-int', 'div-int',
      'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int',
      'ushr-int', 'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long',
      'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long',
      'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float',
      'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double',
      'add-int/2addr', 'sub-int/2addr', 'mul-int/2addr', 'div-int/2addr',
      'add-int/lit16', 'add-int/lit8', 'const/4', 'const/16', 'const/high16',
      'move/from16', 'goto/16', 'goto/32'
    ],
    tokenizer: {
      root: [
        // Comments
        [/#.*$/, 'comment'],
        // Labels
        [/^\s*:[a-zA-Z0-9_]+/, 'label'],
        // Directives / Keywords
        [/\.(class|super|implements|field|method|end\s+method|end\s+annotation|end\s+field|registers|prologue|epilogue|line|source|annotation|param|local|restart|catch|catchall|packed-switch|sparse-switch|array-data)/, 'keyword'],
        // Class modifiers
        [/\b(public|private|protected|static|final|abstract|synthetic|constructor|interface|enum|bridge|native|synchronized)\b/, 'keyword.modifier'],
        // Opcodes
        [/\b(nop|move[\w\-\/]*|return[\w\-]*|const[\w\-\/]*|invoke[\w\-\/]*|iget[\w\-]*|iput[\w\-]*|sget[\w\-]*|sput[\w\-]*|aget[\w\-]*|aput[\w\-]*|add[\w\-\/]*|sub[\w\-\/]*|mul[\w\-\/]*|div[\w\-\/]*|rem[\w\-\/]*|and[\w\-\/]*|or[\w\-\/]*|xor[\w\-\/]*|shl[\w\-]*|shr[\w\-]*|if[\w\-]*|goto[\w\-\/]*|new[\w\-]*|throw|check-cast|instance-of|array-length|monitor[\w\-]*|neg[\w\-]*|not[\w\-]*|int[\w\-]*|long[\w\-]*|float[\w\-]*|double[\w\-]*|filled[\w\-]*|fill[\w\-]*|sparse[\w\-]*|packed[\w\-]*|move[\w\-]*)\b/, 'opcode'],
        // Registers v0-v99, p0-p9
        [/\b[vp]\d+\b/, 'variable'],
        // Type descriptors L...;
        [/L[\w\/\$]+;/, 'type'],
        // Primitive types
        [/\b[ZBCSIJFDV]\b/, 'type.primitive'],
        // Method/field reference arrows
        [/->/, 'operator'],
        // Strings
        [/"(?:[^"\\]|\\.)*"/, 'string'],
        // Numbers (hex)
        [/0x[0-9a-fA-F]+/, 'number.hex'],
        // Numbers (decimal)
        [/\b\d+\b/, 'number'],
        // Boolean
        [/\b(true|false|null)\b/, 'constant'],
        // Whitespace
        [/\s+/, 'white'],
      ]
    }
  });

  // ── Smali Theme ──────────────────────────────────────────────────────────────
  monaco.editor.defineTheme('smali-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'comment',       foreground: '556370', fontStyle: 'italic' },
      { token: 'label',         foreground: 'e5c07b', fontStyle: 'bold' },
      { token: 'keyword',       foreground: 'c678dd' },
      { token: 'keyword.modifier', foreground: '56b6c2' },
      { token: 'opcode',        foreground: '61afef' },
      { token: 'variable',      foreground: 'e06c75' },
      { token: 'type',          foreground: '98c379' },
      { token: 'type.primitive',foreground: '56b6c2' },
      { token: 'string',        foreground: 'e5c07b' },
      { token: 'number',        foreground: 'd19a66' },
      { token: 'number.hex',    foreground: 'd19a66' },
      { token: 'constant',      foreground: 'd19a66' },
      { token: 'operator',      foreground: 'abb2bf' },
    ],
    colors: {
      'editor.background':          '#0e1117',
      'editor.foreground':          '#abb2bf',
      'editor.lineHighlightBackground': '#1a1d26',
      'editor.selectionBackground': '#264f78',
      'editorLineNumber.foreground': '#4b5263',
      'editorLineNumber.activeForeground': '#636d83',
      'editorGutter.background':    '#0e1117',
      'editorWidget.background':    '#13161e',
      'editorSuggestWidget.background': '#13161e',
      'editorSuggestWidget.border': '#333849',
      'editor.findMatchBackground': '#42526e',
      'editor.findMatchHighlightBackground': '#314466',
      'scrollbar.shadow':           '#00000000',
      'scrollbarSlider.background': '#2a2d3799',
      'scrollbarSlider.hoverBackground': '#3d4059',
      'scrollbarSlider.activeBackground': '#4c5073',
      'minimap.background':         '#0e1117',
    }
  });

  // ── Smali Autocomplete ───────────────────────────────────────────────────────
  monaco.languages.registerCompletionItemProvider('smali', {
    provideCompletionItems: (model, position) => {
      const suggestions = [
        // Common smali snippets
        {
          label: 'return-void-method',
          kind: monaco.languages.CompletionItemKind.Snippet,
          insertText: '.registers 1\n    return-void',
          insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
          documentation: 'Empty void method body'
        },
        {
          label: 'return-true',
          kind: monaco.languages.CompletionItemKind.Snippet,
          insertText: '.registers 2\n    const/4 v0, 0x1\n    return v0',
          insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
          documentation: 'Return true (1)'
        },
        {
          label: 'return-false',
          kind: monaco.languages.CompletionItemKind.Snippet,
          insertText: '.registers 2\n    const/4 v0, 0x0\n    return v0',
          insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
          documentation: 'Return false (0)'
        },
        {
          label: 'invoke-virtual',
          kind: monaco.languages.CompletionItemKind.Snippet,
          insertText: 'invoke-virtual {${1:v0}}, L${2:ClassName};->${3:methodName}()${4:V}',
          insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
          documentation: 'Invoke virtual method'
        },
        {
          label: 'const-string',
          kind: monaco.languages.CompletionItemKind.Snippet,
          insertText: 'const-string ${1:v0}, "${2:value}"',
          insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
          documentation: 'Load string constant'
        },
        ...['invoke-virtual','invoke-super','invoke-direct','invoke-static','invoke-interface',
            'return-void','return','return-object','move-result-object','new-instance',
            'const/4','const/16','const-string','iget-object','iput-object','sget-object',
            'sput-object','if-eqz','if-nez','if-eq','if-ne','goto','throw'].map(op => ({
          label: op,
          kind: monaco.languages.CompletionItemKind.Keyword,
          insertText: op
        }))
      ];
      return { suggestions };
    }
  });

  // ── Hover Provider (show opcode descriptions) ────────────────────────────────
  const OPCODE_DOCS = {
    'invoke-virtual': 'Call a virtual method on an object instance',
    'invoke-static':  'Call a static method',
    'invoke-direct':  'Call a method directly (constructor, private)',
    'return-void':    'Return from a void method',
    'const/4':        'Load 4-bit signed integer constant into register',
    'const-string':   'Load a string reference into a register',
    'iget-object':    'Get an instance field (object type)',
    'iput-object':    'Set an instance field (object type)',
    'if-eqz':         'Branch if register == 0 (false)',
    'if-nez':         'Branch if register != 0 (true)',
  };

  monaco.languages.registerHoverProvider('smali', {
    provideHover: (model, position) => {
      const word = model.getWordAtPosition(position);
      if (word && OPCODE_DOCS[word.word]) {
        return {
          contents: [
            { value: `**${word.word}** — smali opcode` },
            { value: OPCODE_DOCS[word.word] }
          ]
        };
      }
    }
  });

  // ── Create Editor ────────────────────────────────────────────────────────────
  window.monacoEditor = monaco.editor.create(document.getElementById('monaco-editor'), {
    value: '',
    language: 'smali',
    theme: 'smali-dark',
    fontSize: 13,
    fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
    fontLigatures: true,
    lineNumbers: 'on',
    minimap: { enabled: true, maxColumn: 60 },
    scrollBeyondLastLine: false,
    wordWrap: 'off',
    renderWhitespace: 'selection',
    cursorBlinking: 'smooth',
    cursorSmoothCaretAnimation: 'on',
    smoothScrolling: true,
    automaticLayout: true,
    tabSize: 4,
    insertSpaces: true,
    folding: true,
    bracketPairColorization: { enabled: true },
    guides: { bracketPairs: true, indentation: true },
    renderLineHighlight: 'line',
    scrollbar: { verticalScrollbarSize: 6, horizontalScrollbarSize: 6 },
    padding: { top: 8, bottom: 8 },
    suggest: { showKeywords: true, showSnippets: true },
    quickSuggestions: { other: true, comments: false, strings: false },
  });

  // ── Editor Keyboard Shortcuts ────────────────────────────────────────────────
  window.monacoEditor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
    window.dispatchEvent(new Event('editor-save'));
  });

  // ── Context Menu ─────────────────────────────────────────────────────────────
  window.monacoEditor.onContextMenu((e) => {
    e.event.preventDefault();
    window.dispatchEvent(new CustomEvent('editor-context-menu', {
      detail: {
        x: e.event.posx,
        y: e.event.posy,
        position: e.target.position,
        lineContent: window.monacoEditor.getModel()
          ? window.monacoEditor.getModel().getLineContent(e.target.position?.lineNumber || 1)
          : ''
      }
    }));
  });

  // ── Language detection by extension ──────────────────────────────────────────
  window.getLanguageForExt = function(ext) {
    const map = {
      '.smali': 'smali', '.java': 'java', '.xml': 'xml', '.json': 'json',
      '.kt': 'kotlin', '.gradle': 'groovy', '.js': 'javascript', '.md': 'markdown',
      '.txt': 'plaintext', '.so': 'plaintext', '.dex': 'plaintext'
    };
    return map[ext] || 'plaintext';
  };

  window.openFileInEditor = function(content, ext, filename) {
    const lang = window.getLanguageForExt(ext);
    const model = monaco.editor.createModel(content, lang);
    window.monacoEditor.setModel(model);
    monaco.editor.setTheme(lang === 'smali' ? 'smali-dark' : 'vs-dark');
    window.monacoEditor.setScrollPosition({ scrollTop: 0 });
    document.getElementById('monaco-editor').style.display = 'block';
    const welcome = document.getElementById('editor-welcome');
    if (welcome) welcome.style.display = 'none';
  };

  window.getEditorContent = function() {
    const model = window.monacoEditor.getModel();
    return model ? model.getValue() : '';
  };

  window.highlightLine = function(lineNumber) {
    window.monacoEditor.revealLineInCenter(lineNumber);
    window.monacoEditor.setPosition({ lineNumber, column: 1 });
    window.monacoEditor.deltaDecorations([], [{
      range: new monaco.Range(lineNumber, 1, lineNumber, 1),
      options: { isWholeLine: true, className: 'line-highlight-anim', linesDecorationsClassName: 'line-highlight-gutter' }
    }]);
  };

  // ─ Ready signal ──────────────────────────────────────────────────────────────
  window.monacoReady = true;
  window.monacoReadyCallbacks.forEach(cb => cb());
  window.dispatchEvent(new Event('monaco-ready'));
  console.log('[APK Studio] Monaco Editor initialized');
});
