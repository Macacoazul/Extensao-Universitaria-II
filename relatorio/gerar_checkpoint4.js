// Gera relatorio/Checkpoint4.docx (modelo CHECKPOINT-4 da disciplina, estilo dos CP1/CP2)
// Uso: node relatorio/gerar_checkpoint4.js   (na raiz do projeto)
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, AlignmentType,
  HeadingLevel, WidthType, ShadingType, BorderStyle, LevelFormat, PageBreak, Footer, PageNumber,
} = require("docx");

const ROOT = path.resolve(__dirname, "..");
const FONT = "Times New Roman";
const PAGE_W = 9638; // largura util A4 com margens de 2 cm (DXA)
let fig = 0, tab = 0;

// ------------------------------------------------------------------ helpers
const run = (t, o = {}) => new TextRun({ text: t, font: FONT, size: 24, ...o });
const P = (children, o = {}) => new Paragraph({
  alignment: AlignmentType.JUSTIFIED, spacing: { line: 360, after: 120 }, indent: { firstLine: 709 },
  children: (Array.isArray(children) ? children : [children]).map(c => typeof c === "string" ? run(c) : c), ...o,
});
const PN = (children, o = {}) => P(children, { indent: { firstLine: 0 }, ...o });
const C = (t, o = {}) => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 },
  children: [run(t, o)] });
const H1 = t => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: t })] });
const H2 = t => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun({ text: t })] });
const H3 = t => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun({ text: t })] });
const B = (t, o = {}) => run(t, { bold: true, ...o });
const I = t => run(t, { italics: true });
const HL = t => run(t, { highlight: "yellow" });
const bullet = (children, level = 0) => new Paragraph({
  numbering: { reference: "bullets", level }, spacing: { line: 300, after: 60 }, alignment: AlignmentType.JUSTIFIED,
  children: (Array.isArray(children) ? children : [children]).map(c => typeof c === "string" ? run(c) : c),
});
const num = (children, ref = "num") => new Paragraph({
  numbering: { reference: ref, level: 0 }, spacing: { line: 300, after: 60 }, alignment: AlignmentType.JUSTIFIED,
  children: (Array.isArray(children) ? children : [children]).map(c => typeof c === "string" ? run(c) : c),
});
const code = lines => lines.map(l => new Paragraph({ spacing: { after: 0, line: 240 },
  shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" },
  children: [new TextRun({ text: l || " ", font: "Courier New", size: 17 })] }));

function pngSize(file) {
  const b = fs.readFileSync(file);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

function figura(rel, legenda, maxW = 600, maxH = 760) {
  const file = path.join(ROOT, rel);
  const { w, h } = pngSize(file);
  let width = maxW, height = Math.round(h * maxW / w);
  if (height > maxH) { height = maxH; width = Math.round(w * maxH / h); }
  fig += 1;
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 40 }, keepNext: true,
      children: [new ImageRun({ type: "png", data: fs.readFileSync(file), transformation: { width, height },
        altText: { title: legenda, description: legenda, name: path.basename(rel) } })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
      children: [run(`Figura ${fig}: ${legenda}`, { size: 20, italics: true })] }),
  ];
}

const border = { style: BorderStyle.SINGLE, size: 4, color: "999999" };
const borders = { top: border, bottom: border, left: border, right: border };
function tabela(titulo, headers, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const scale = PAGE_W / total;
  const ws = widths.map(w => Math.floor(w * scale));
  ws[ws.length - 1] = PAGE_W - ws.slice(0, -1).reduce((a, b) => a + b, 0);
  const cell = (t, i, head) => new TableCell({
    borders, width: { size: ws[i], type: WidthType.DXA },
    shading: head ? { type: ShadingType.CLEAR, fill: "D9E2F3", color: "auto" } : undefined,
    margins: { top: 50, bottom: 50, left: 80, right: 80 },
    children: String(t).split("\n").map(line => new Paragraph({ spacing: { after: 0, line: 240 },
      children: [new TextRun({ text: line, font: FONT, size: 18, bold: head })] })),
  });
  tab += 1;
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 160, after: 60 }, keepNext: true,
      children: [run(`Quadro ${tab}: ${titulo}`, { size: 20, bold: true })] }),
    new Table({ width: { size: PAGE_W, type: WidthType.DXA }, columnWidths: ws,
      rows: [new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, i, true)) }),
        ...rows.map(r => new TableRow({ children: r.map((c, i) => cell(c, i, false)) }))] }),
    new Paragraph({ spacing: { after: 120 }, children: [] }),
  ];
}

const aviso = (texto) => new Paragraph({
  spacing: { before: 120, after: 160, line: 300 }, alignment: AlignmentType.JUSTIFIED,
  shading: { type: ShadingType.CLEAR, fill: "FFF2CC", color: "auto" },
  border: { top: { style: BorderStyle.SINGLE, size: 6, color: "BF8F00", space: 4 },
    bottom: { style: BorderStyle.SINGLE, size: 6, color: "BF8F00", space: 4 },
    left: { style: BorderStyle.SINGLE, size: 6, color: "BF8F00", space: 4 },
    right: { style: BorderStyle.SINGLE, size: 6, color: "BF8F00", space: 4 } },
  children: texto.map(c => typeof c === "string" ? run(c, { size: 22 }) : c),
});

// ------------------------------------------------------------------ dados dos testes
const T = n => JSON.parse(fs.readFileSync(path.join(ROOT, `testes/T${n}.json`), "utf8"));
const testes = [1, 2, 3, 4, 5, 6].map(T);
const hora = s => s.slice(11, 19);
const NOMES = ["Varredura de portas do Cliente para o Servidor (situação hipotética)",
  "Força bruta SSH no Servidor (situação hipotética)",
  "Assinatura de teste do Suricata (página no estilo testmynids em site fictício)",
  "Alteração de arquivo monitorado (FIM)",
  "Tráfego bloqueado pelo firewall (LAN → serviços da gerência)",
  "Reincidência do teste 2 (situação hipotética)"];
testes.forEach((t, i) => { t.meta.nome = NOMES[i]; });
const regras = t => t.regras.map(r => `${r.rule_id} (nível ${r.level}, ${r.count}x)`).join("\n");
const analiseIA = t => t.incidentes.map(i => {
  const a = JSON.parse(i.analysis);
  return `${i.id}: ${a.classificacao}/${a.gravidade}` + (i.recurrence ? " — REINCIDÊNCIA" : "") + `\nação: ${i.action}`;
}).join("\n");
const totalAlertas = fs.readFileSync("/var/ossec/logs/alerts/alerts.json", "utf8").split("\n").filter(Boolean).length;

// ------------------------------------------------------------------ conteudo
const C_ = [];
const add = (...x) => x.flat().forEach(e => C_.push(e));

// Cabecalho igual ao dos Checkpoints 1 e 2 (logo do IFC, texto a esquerda, logo do BSI a direita)
const SEM_BORDA = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const semBordas = { top: SEM_BORDA, bottom: SEM_BORDA, left: SEM_BORDA, right: SEM_BORDA };
const linhaCab = (children) => new Paragraph({ spacing: { after: 0, line: 240 }, alignment: AlignmentType.LEFT,
  children: children.map(c => typeof c === "string" ? run(c) : c) });
const logoIFC = fs.readFileSync(path.join(ROOT, "relatorio/diagramas/logo_ifc.png"));
const logoBSI = fs.readFileSync(path.join(ROOT, "relatorio/diagramas/logo_bsi.png"));
const COL_TXT = 7600, COL_LOGO = PAGE_W - 7600;
add(
  new Paragraph({ spacing: { after: 200 }, children: [new ImageRun({ type: "png", data: logoIFC,
    transformation: { width: 290, height: 72 },
    altText: { title: "Instituto Federal Catarinense - Campus Camboriú", description: "Logo do IFC Campus Camboriú", name: "logo_ifc" } })] }),
  new Table({
    width: { size: PAGE_W, type: WidthType.DXA }, columnWidths: [COL_TXT, COL_LOGO],
    borders: { ...semBordas, insideHorizontal: SEM_BORDA, insideVertical: SEM_BORDA },
    rows: [new TableRow({ children: [
      new TableCell({ borders: semBordas, width: { size: COL_TXT, type: WidthType.DXA }, verticalAlign: "center",
        children: [
          linhaCab([B("Curso Superior de Bacharelado em Sistemas de Informação - BSI")]),
          linhaCab([B("Disciplina de Extensão Universitária II (2026.2)")]),
          linhaCab(["Professores: André Fabiano de Moraes / Filipe William Canello de Almeida"]),
          linhaCab(["Atividade: CHECKPOINT - 4 (Relatório Final do Projeto de Extensão Universitária II)"]),
          linhaCab(["Nome do Estudante: Matheus Souza da Silva"]),
        ] }),
      new TableCell({ borders: semBordas, width: { size: COL_LOGO, type: WidthType.DXA }, verticalAlign: "center",
        children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new ImageRun({ type: "png", data: logoBSI,
          transformation: { width: 96, height: 96 },
          altText: { title: "Bacharelado em Sistemas de Informação", description: "Logo do curso de BSI", name: "logo_bsi" } })] })] }),
    ] })],
  }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 360, after: 360 },
    children: [run("Monitoramento Inteligente de Redes para Detecção de Ameaças e Anomalias", { bold: true })] }),
);

add(
  PN([B("Resumo: "), "O crescimento do uso de computadores, dispositivos móveis, serviços em nuvem e equipamentos " +
    "conectados à Internet tornou as redes de computadores essenciais para empresas e organizações, aumentando também a " +
    "necessidade de práticas de segurança, monitoramento e identificação de atividades suspeitas. Este relatório final " +
    "apresenta o desenvolvimento do projeto de extensão, que integrou ações de ensino, pesquisa e extensão voltadas ao " +
    "monitoramento inteligente de redes. Na parte técnica, foi construída uma arquitetura de laboratório em Docker composta " +
    "por firewall (regras equivalentes às de um pfSense, implementadas com nftables), servidor e estação Ubuntu, sensor IDS " +
    "Suricata, SIEM Wazuh e um serviço de Inteligência Artificial (ai-analyst) que analisa os alertas com um modelo de " +
    "linguagem local (DeepSeek-R1 via Ollama), guarda o histórico de incidentes para reconhecer reincidências e recomenda " +
    "ou aplica bloqueios. A arquitetura foi demonstrada em um ambiente experimental com máquinas simuladas e situações " +
    `hipotéticas, no qual seis cenários de teste geraram ${totalAlertas} alertas no formato do Wazuh. Todos os cenários ` +
    "foram detectados; a reincidência da tentativa de força bruta SSH foi reconhecida pela IA, que aplicou automaticamente " +
    "o bloqueio da origem no firewall e no servidor. Como limitação, o modelo de linguagem não pôde ser executado no ambiente " +
    "experimental, e as análises foram produzidas pelo modo de contingência do serviço. Os resultados, o código e a " +
    "documentação servem de base para a continuidade da pesquisa no Trabalho de Conclusão de Curso."]),
  PN([B("Nota sobre os testes: "), "os testes apresentados neste relatório foram realizados a partir de um ambiente " +
    "experimental com situações hipotéticas. As máquinas da rede foram simuladas (namespaces de rede Linux) e parte dos " +
    "eventos — varredura de portas e tentativas de login SSH — foi produzida como registro hipotético, sem execução real " +
    "de ataques. O objetivo é demonstrar o funcionamento da arquitetura proposta; os resultados não representam uma rede " +
    "de produção."]),
  PN([B("Palavras-Chave: "), "Projeto; Curricularização da Extensão; Ações Integradas; Redes de Computadores; " +
    "Cibersegurança; Monitoramento de Redes; Detecção de Anomalias; Segurança da Informação; SIEM; Inteligência Artificial."]),
);

// I - Introducao
add(H1("I – Introdução / Justificativa"),
  P("A transformação digital ampliou o uso de computadores, dispositivos móveis, redes sem fio, serviços em nuvem e outros " +
    "recursos tecnológicos nas atividades de empresas e organizações. Com isso, a segurança das redes de computadores " +
    "tornou-se uma necessidade também para pequenos negócios, que muitas vezes possuem infraestrutura reduzida e poucos " +
    "recursos especializados em cibersegurança."),
  P("Nesse contexto, o monitoramento de redes permite acompanhar conexões, protocolos, portas, volume de dados e eventos que " +
    "podem indicar comportamentos fora do padrão esperado. Ferramentas como Suricata, Zeek e Wazuh auxiliam na coleta, " +
    "análise e centralização dessas informações, permitindo identificar ameaças conhecidas e atividades que mereçam " +
    "investigação. Como referências conceituais, foram adotados o NIST Cybersecurity Framework 2.0, principalmente a função " +
    "DETECT, e o MITRE ATT&CK, utilizado para classificar os comportamentos observados nos testes."),
  P("Nesta etapa final, o projeto avançou da proposta (Checkpoint 1) e do relatório parcial (Checkpoint 2) para a " +
    "implementação do laboratório e de um componente de Inteligência Artificial que apoia a análise dos alertas. A " +
    "justificativa para incluir a IA é reduzir o esforço de triagem: em uma rede pequena, com pouco ou nenhum pessoal " +
    "dedicado à segurança, receber um resumo interpretado do incidente, com causa provável, técnica do MITRE ATT&CK e ação " +
    "recomendada, é mais útil do que dezenas de alertas isolados. Ao mesmo tempo, o projeto mantém o caráter extensionista " +
    "de aproximar esses conhecimentos de pequenos negócios e da comunidade, por meio de ações de conscientização sobre boas " +
    "práticas de segurança digital, em conformidade com as Diretrizes para a Extensão na Educação Superior Brasileira."),
);

// II - Objetivos
add(H1("II – Objetivos (Geral e Específicos)"),
  P([B("Objetivo geral: "), "desenvolver ações integradas de ensino, pesquisa e extensão relacionadas ao monitoramento " +
    "inteligente de redes e à segurança cibernética, promovendo a conscientização de pequenos negócios e/ou membros da " +
    "comunidade sobre boas práticas de segurança digital e desenvolvendo um ambiente experimental para estudo de técnicas " +
    "de monitoramento, detecção de ameaças e identificação de comportamentos anômalos em redes de computadores."]),
  PN([B("Objetivos específicos:")]),
  num("Projetar e implementar um laboratório virtualizado com firewall, servidor, estação cliente, sensor IDS e SIEM."),
  num("Configurar o Suricata para inspecionar o tráfego da rede local e registrar alertas e eventos (EVE JSON)."),
  num("Centralizar os eventos no Wazuh: agentes nos hosts, monitoramento de integridade de arquivos (FIM), logs do firewall via syslog e regras personalizadas."),
  num("Desenvolver um serviço de IA (ai-analyst) com modelo de linguagem local, memória de incidentes (RAG) e recomendações de prevenção."),
  num("Executar e documentar cenários de teste controlados, mapeados ao MITRE ATT&CK."),
  num("Analisar os resultados: detecções, falsos positivos, reincidência e limitações da solução."),
  num("Produzir materiais e ações de conscientização em segurança de redes para pequenos negócios e comunidade."),
);

// III - Metodologia
add(H1("III – Metodologia"),
  P("O projeto foi conduzido de forma aplicada e incremental, em fases com critério objetivo de validação ao final de cada " +
    "uma. A revisão bibliográfica (Ação 1) fundamentou os conceitos de monitoramento, IDS/IPS, SIEM, detecção de anomalias, " +
    "NIST CSF 2.0 e MITRE ATT&CK. Em paralelo, foram planejadas as ações extensionistas (Ação 2). A construção do laboratório " +
    "(Ação 3) seguiu as fases: (1) infraestrutura de rede; (2) firewall; (3) sensor IDS; (4) SIEM; (5) Inteligência " +
    "Artificial; (6) testes; (7) capturas de tela; e (8) documentação."),
  P("Toda a infraestrutura foi descrita como código: arquivo docker-compose.yml, configurações de cada serviço em pastas " +
    "próprias, scripts de operação (lab.ps1) e o serviço ai-analyst em Python, com testes automatizados. O repositório é " +
    "versionado com Git, o que permite reproduzir o ambiente e rastrear cada decisão, registrada no arquivo PROGRESSO.md."),
  P([B("Ambiente experimental com situações hipotéticas. "), "Para demonstrar o funcionamento completo da arquitetura, os " +
    "testes foram executados em um ambiente experimental no qual as máquinas do laboratório foram simuladas com namespaces " +
    "de rede Linux, com os mesmos endereços e regras do projeto. O Quadro 1 mostra o que foi executado de fato e o que foi " +
    "simulado ou hipotético."]),
  tabela("Natureza de cada componente no ambiente experimental",
    ["Componente", "Como foi executado", "Natureza"],
    [["Firewall (nftables, ulogd2, rsyslog, API de bloqueio)", "Mesmos arquivos e o mesmo script de inicialização do container do projeto, em uma máquina simulada", "Real (máquina simulada)"],
     ["Servidor e cliente", "Máquinas simuladas com IPs 192.168.10.10 e 192.168.10.20; nginx e sshd reais no servidor", "Real (máquinas simuladas)"],
     ["Internet", "Site fictício 198.51.100.10 (faixa reservada para documentação, RFC 5737)", "Simulado"],
     ["Suricata 7.0.3", "Escutando a bridge da LAN em modo promíscuo", "Real"],
     ["SIEM", "Emulador que coleta os mesmos logs e grava alertas no formato do Wazuh, com as regras do projeto e as regras padrão do Wazuh usadas nos testes (IDs, níveis e frequências do ruleset oficial)", "Emulado"],
     ["ai-analyst", "Código do projeto, sem alterações; LLM indisponível no ambiente, então as análises usaram o modo de contingência (playbooks)", "Real (sem LLM)"],
     ["Testes 1, 2 e 6", "Varredura e tentativas de login produzidas como registros hipotéticos (sem execução de ataques)", "Hipotético"],
     ["Testes 3, 4 e 5", "Executados de fato dentro do ambiente experimental", "Real"]],
    [2.2, 4.6, 1.6]),
  P("Para cada teste foram registrados o comando, o horário de início e fim, o resultado esperado, o resultado obtido, os " +
    "alertas gerados (ID da regra e nível) e a análise da IA. A extração das evidências foi automatizada pelo módulo " +
    "analyst.evidencias, que gera os arquivos testes/T1.md a T6.md. As capturas de tela foram geradas com o Playwright, em " +
    "modo headless, a partir dos artefatos da execução, e todas trazem a faixa \"Ambiente experimental\"."),
  P("Todos os cenários foram executados exclusivamente dentro do laboratório, contra as próprias máquinas do laboratório, " +
    "sem malware real e sem coleta de dados de terceiros, em consonância com a LGPD e com a ética da pesquisa."),
);

// IV - Desenvolvimento
add(H1("IV – Desenvolvimento"),
  P("Este capítulo descreve o escopo do projeto e os artefatos de análise e projeto, seguindo os itens do modelo da " +
    "disciplina, e apresenta a arquitetura implementada."),
  H2("a) Processos de Análise e Projeto de Sistemas"),
  P("Adotou-se um processo incremental e iterativo: cada fase entrega um incremento funcional com critério de aceitação " +
    "verificável. O Quadro 2 resume as fases, as entregas e a validação."),
  tabela("Fases do desenvolvimento e critérios de validação",
    ["Fase", "Entrega", "Validação"],
    [["1 – Infraestrutura", "Redes WAN, LAN e gerência; servidor e cliente com rota padrão no firewall", "ping, rotas e acesso externo passando pelo firewall"],
     ["2 – Firewall", "Política default deny, NAT de saída e logs via syslog", "tráfego liberado × bloqueado e logs no SIEM"],
     ["3 – Sensor", "Suricata na bridge da LAN, EVE JSON lido pelo SIEM", "eventos e alertas no eve.json"],
     ["4 – SIEM", "Wazuh single-node, agentes, FIM, decoders e regras", "alertas de SSH, FIM, IDS e firewall"],
     ["5 – IA", "ai-analyst: triagem, análise, memória, prevenção e saúde", "relatórios em ia/ e testes automatizados"],
     ["6 a 8", "Testes, prints e relatório", "evidências T1 a T6 e este documento"]],
    [1.6, 4.2, 3.2]),
  H2("b) Análise e Projeto de Sistemas de Informação Orientados a Objetos"),
  P("O serviço ai-analyst foi projetado de forma modular, com classes de responsabilidade única. Isso permite testar cada " +
    "parte isoladamente e trocar componentes, por exemplo o modelo de linguagem ou o banco de dados, sem alterar o restante."),
  tabela("Principais classes e módulos do ai-analyst",
    ["Classe / módulo", "Responsabilidade"],
    [["AlertTailer (alerts.py)", "Ler o alerts.json do Wazuh de forma incremental, com estado persistido e tratamento de rotação"],
     ["Alert", "Encapsular um alerta: regra, nível, MITRE, origem, destino e categoria"],
     ["Triage / Incident (triage.py)", "Selecionar alertas relevantes (nível ≥ 7 ou agrupados por origem) e agrupar rajadas em incidentes"],
     ["Memory (memory.py)", "Persistir incidentes em SQLite com embeddings; buscar reincidências e casos semelhantes (RAG)"],
     ["OllamaClient (llm.py)", "Consultar o LLM local com saída JSON estruturada; gerar embeddings"],
     ["prevention.py", "Planejar e, com AUTO_BLOCK, aplicar bloqueios com salvaguardas (só IPs do lab, nunca IPs protegidos)"],
     ["WazuhAPI (wazuh_api.py)", "Consultar agentes e disparar o active response firewall-drop"],
     ["health.py / reports.py", "Relatório de saúde e arquivos de recomendações e histórico"]],
    [3, 7]),
  H2("c) Requisitos (funcionais e não funcionais)"),
  tabela("Requisitos funcionais",
    ["ID", "Requisito"],
    [["RF01", "Rotear o tráfego da LAN pelo firewall, com NAT de saída e política de negação por padrão"],
     ["RF02", "Registrar o tráfego bloqueado e enviá-lo ao SIEM via syslog"],
     ["RF03", "Inspecionar o tráfego da LAN com assinaturas (Suricata) e gerar EVE JSON"],
     ["RF04", "Centralizar alertas de agentes, IDS e firewall no SIEM, com regras personalizadas e mapeamento MITRE"],
     ["RF05", "Monitorar a integridade de /etc e /var/www (FIM)"],
     ["RF06", "Agrupar alertas em incidentes e analisá-los com IA (classificação, gravidade, causa, MITRE, ação)"],
     ["RF07", "Manter histórico de incidentes e detectar reincidência da mesma origem"],
     ["RF08", "Recomendar ações de prevenção e, se habilitado, aplicar bloqueio apenas a IPs do laboratório"],
     ["RF09", "Gerar relatório periódico de saúde dos serviços, agentes e sensor"],
     ["RF10", "Extrair as evidências de cada teste (alertas e análises) em arquivo"]],
    [1, 9]),
  tabela("Requisitos não funcionais",
    ["ID", "Requisito"],
    [["RNF01", "Reprodutibilidade: infraestrutura como código (Docker Compose), versões fixadas e repositório Git"],
     ["RNF02", "Segurança: credenciais somente no arquivo .env (fora do Git); portas publicadas apenas em 127.0.0.1"],
     ["RNF03", "Privacidade: IA executada localmente (Ollama), sem envio de logs a serviços externos"],
     ["RNF04", "Prevenção conservadora: bloqueio automático desligado por padrão e, quando ligado, só em reincidência"],
     ["RNF05", "Manutenibilidade: código modular, testes automatizados e configuração por variáveis de ambiente"],
     ["RNF06", "Ética: testes apenas no laboratório isolado, sem malware e sem dados de terceiros"]],
    [1, 9]),
  H2("d) Casos de Uso de Alto Nível"),
  P("O diagrama de casos de uso elaborado no Checkpoint 2 (Figura 1) permanece válido. O ator Pesquisador/Extensionista " +
    "configura o ambiente, coleta dados, detecta anomalias e gera relatórios; a detecção e a geração de relatórios incluem " +
    "a consulta aos eventos coletados."),
  figura("relatorio/diagramas/casos_de_uso_cp2.png", "Diagrama de casos de uso do sistema (Checkpoint 2)", 520),
  H2("e) Casos de Uso Expandidos"),
  tabela("Caso de uso expandido — Detectar Anomalias (análise de incidente pela IA)",
    ["Item", "Descrição"],
    [["Ator principal", "Pesquisador / Extensionista; ator de apoio: ai-analyst (sistema)"],
     ["Pré-condições", "SIEM recebendo eventos; ai-analyst em execução; regras do laboratório carregadas"],
     ["Fluxo principal", "1. Um evento gera alerta no SIEM.\n2. O ai-analyst lê o alerta e o agrupa em um incidente.\n3. O sistema consulta o histórico da mesma origem e casos semelhantes.\n4. O LLM devolve classificação, gravidade, causa, MITRE e ação.\n5. O sistema grava a análise e a recomendação em ia/recomendacoes.md.\n6. O pesquisador revisa e aprova (ou não) o bloqueio."],
     ["Fluxos alternativos", "4a. LLM indisponível: análise pelo modo de contingência (playbooks).\n5a. Reincidência com AUTO_BLOCK=true: o bloqueio é aplicado automaticamente no firewall e no servidor.\n5b. IP fora do laboratório ou protegido: o bloqueio é recusado e apenas registrado."],
     ["Pós-condições", "Incidente registrado no histórico, com análise, ação e embedding"]],
    [2, 8]),
  tabela("Caso de uso expandido — Consultar Eventos Coletados",
    ["Item", "Descrição"],
    [["Ator principal", "Pesquisador / Extensionista"],
     ["Pré-condições", "Teste executado com horário de início e fim registrados"],
     ["Fluxo principal", "1. O pesquisador informa o teste e a janela de tempo.\n2. O sistema lê os alertas do período.\n3. O sistema agrupa por regra (ID, nível, quantidade, origem, agente, MITRE).\n4. O sistema anexa as análises da IA do período.\n5. O sistema grava testes/T<n>.md e T<n>.json."],
     ["Extensão", "Não há eventos registrados: o relatório informa \"nenhum alerta encontrado no intervalo\""],
     ["Pós-condições", "Evidências do teste disponíveis para o relatório"]],
    [2, 8]),
  H2("f) Diagrama de Sequência de Sistemas – DSS"),
  P("A Figura 2 apresenta a sequência do cenário de tentativa de força bruta SSH, desde a geração dos eventos até a " +
    "recomendação ou o bloqueio."),
  figura("relatorio/diagramas/dss_analise_incidente.png", "DSS da análise de incidente com IA e prevenção"),
  H2("g) Modelagem Conceitual do Banco de Dados (Lógico e Físico)"),
  P("No modelo conceitual (Figura 3), alertas disparados por regras são agrupados em incidentes. Cada incidente recebe " +
    "uma análise, pode gerar ações e pode referenciar incidentes anteriores da mesma origem (reincidência). No modelo " +
    "físico, por simplicidade e volume de laboratório, os dados do incidente, da análise (JSON) e da ação ficam em uma " +
    "tabela SQLite, mantida em volume Docker, enquanto os alertas permanecem no alerts.json do Wazuh."),
  figura("relatorio/diagramas/modelo_dados.png", "Modelo conceitual dos dados do ai-analyst", 600, 620),
  PN([B("Modelo físico (SQLite):")]),
  ...code(["CREATE TABLE incidents (", "  id TEXT PRIMARY KEY,          -- INC-xxxxxxxxxx",
    "  created_at REAL NOT NULL,     first_ts TEXT,  last_ts TEXT,",
    "  key TEXT,  category TEXT,  srcip TEXT,  agents TEXT,  rule_ids TEXT,",
    "  max_level INTEGER,  alert_count INTEGER,  summary TEXT,",
    "  analysis TEXT,                -- JSON: classificacao, gravidade, causa, mitre, acao...",
    "  recurrence INTEGER DEFAULT 0,  prior_count INTEGER DEFAULT 0,",
    "  action TEXT,  embedding BLOB  -- vetor float32 para busca por similaridade", ");",
    "CREATE INDEX ix_inc_src ON incidents(srcip, category);"]),
  new Paragraph({ spacing: { after: 120 }, children: [] }),
  H2("h) Modelagem Funcional (Contratos)"),
  tabela("Contratos das operações do sistema",
    ["Operação", "Pré-condições", "Pós-condições"],
    [["analisarIncidente(incidente)", "Incidente com ao menos um alerta; histórico acessível", "Análise registrada; reincidência calculada; recomendação gravada em ia/recomendacoes.md"],
     ["aplicarBloqueio(ip, agente)", "AUTO_BLOCK=true ou aprovação manual; IP dentro de 192.168.10.0/24 e fora da lista de protegidos", "IP na blocklist do firewall (timeout 1h); regra DROP no agente; evento 100104/651 no SIEM; ação registrada"],
     ["registrarTeste(id, início, fim)", "Janela de tempo válida", "Arquivos testes/T<id>.md e .json com alertas e análises do período"],
     ["verificarSaude()", "Serviços acessíveis pela rede de gerência", "ia/saude.md atualizado com estado dos serviços, agentes, Suricata e modelo"]],
    [2.6, 3.4, 4]),
  H2("Arquitetura implementada"),
  P("A Figura 4 apresenta a arquitetura implementada em Docker. As principais decisões e desvios em relação ao planejado " +
    "estão no Quadro 10."),
  figura("relatorio/diagramas/arquitetura.png", "Arquitetura do laboratório em Docker (WAN, LAN e gerência)"),
  tabela("Endereçamento do laboratório",
    ["Componente", "Endereço(s)", "Função"],
    [["Firewall", "WAN 172.20.0.2 · LAN 192.168.10.1 · MGMT 172.30.0.2", "Roteamento, NAT, default deny, syslog, API de bloqueio"],
     ["Ubuntu Server", "192.168.10.10", "SSH, Nginx, agente Wazuh, FIM"],
     ["Ubuntu Cliente", "192.168.10.20", "Estação de usuário e origem dos testes"],
     ["Wazuh manager / indexer / dashboard", "172.30.0.10 / .11 / .12", "SIEM (single-node oficial 4.14.10)"],
     ["Ollama / ai-analyst", "172.30.0.20 / .21", "LLM local e serviço de análise"],
     ["Suricata", "rede do host, escutando br-lab-lan", "IDS por assinaturas (ET Open + regras locais)"]],
    [2.6, 3.6, 3.8]),
  tabela("Decisões e desvios em relação à proposta",
    ["Tema", "Decisão", "Justificativa"],
    [["pfSense", "Firewall Linux com nftables replicando as regras (opção c)", "O pfSense é baseado em FreeBSD e não roda como container; em host Windows não há KVM disponível no Docker e uma VM no VirtualBox não alcança as redes do Docker Desktop"],
     ["Posição do sensor", "Suricata na bridge da LAN em modo promíscuo", "O tráfego Cliente↔Servidor é comutado pela bridge e não passa pelo firewall; no namespace do firewall os testes 1, 2 e 6 ficariam invisíveis"],
     ["Zeek", "Não utilizado nesta etapa", "O escopo da disciplina priorizou Suricata e Wazuh; o Zeek fica para o TCC"],
     ["Modelo de IA", "DeepSeek-R1 8B (padrão), Hermes 3 8B como alternativa", "A tarefa é analítica (correlacionar, inferir causa, mapear ATT&CK); o DeepSeek-R1 é um modelo de raciocínio. O Hermes 3 é mais rápido e segue bem formatos, sendo indicado para hardware modesto. A saída JSON é garantida pelo structured output do Ollama"],
     ["Prevenção", "Recomendar por padrão; bloqueio automático só com AUTO_BLOCK=true e em reincidência", "Evitar que um falso positivo isolado interrompa serviços"],
     ["Memória da IA", "SQLite + embeddings (em vez de ChromaDB)", "Volume pequeno de laboratório; menos dependências"]],
    [1.6, 3, 5.4]),
  P("A Figura 5 mostra o ambiente experimental utilizado nos testes, com as máquinas simuladas e o emulador do SIEM."),
  figura("relatorio/diagramas/ambiente_experimental.png", "Topologia do ambiente experimental (máquinas simuladas)"),
);

// V - Resultados
add(H1("V – Resultados Alcançados"),
  P("Todos os resultados desta seção foram obtidos a partir de um ambiente experimental com situações hipotéticas, " +
    "executado em 12/11/2026 entre 22:53 e 22:58 (horário de Brasília)."),
  H2("Infraestrutura e firewall (Fases 1 e 2)"),
  P("As máquinas simuladas receberam os endereços previstos, e cliente e servidor passaram a ter rota padrão no firewall " +
    "(192.168.10.1). O ping ao firewall, ao servidor e ao site externo fictício teve 0% de perda. O site externo registrou " +
    "a requisição como vinda de 172.20.0.2, o IP WAN do firewall, o que comprova o NAT de saída (Figura 6)."),
  ...figura("prints/03_fase1_ping_rotas_nat.png", "Fase 1 — endereços, rotas, ping e NAT de saída (ambiente experimental)", 560, 700),
  P("Na Fase 2, o acesso HTTP à internet foi liberado (HTTP 200). Já as tentativas de telnet (porta 23) e de acesso da " +
    "LAN à API do SIEM na rede de gerência foram bloqueadas e registradas (FW-DROP), gerando a regra 100101 no SIEM " +
    "(Figura 7). As regras ativas aparecem na Figura 8."),
  figura("prints/04_fase2_firewall_liberado_bloqueado.png", "Fase 2 — tráfego liberado e bloqueado, log do firewall e alerta 100101"),
  figura("prints/05_firewall_regras_nftables.png", "Regras ativas do firewall (nft list ruleset)", 560, 640),
  H2("Sensor IDS e SIEM (Fases 3 e 4)"),
  P("O Suricata 7.0.3 iniciou escutando a bridge br-lab-lan e passou a registrar eventos de fluxo, HTTP e alertas no " +
    "eve.json. O emulador do SIEM coletou syslog do firewall, eve.json, auth.log do servidor e o FIM de /etc e /var/www " +
    "(Figura 9)."),
  figura("prints/06_fase3_suricata_e_siem.png", "Fases 3 e 4 — Suricata ativo, eventos no eve.json e coleta pelo SIEM"),
  H2("Inteligência Artificial (Fase 5)"),
  P("O ai-analyst iniciou normalmente. Como o Ollama não pôde ser executado no ambiente experimental, o serviço registrou a " +
    "indisponibilidade do LLM e passou a operar em modo de contingência. Nesse modo, a análise usa playbooks por categoria " +
    "e os dados do incidente, e a memória usa embeddings locais. O relatório de saúde gerado pela IA (Figura 10) apontou " +
    "corretamente essa situação: Ollama e modelo indisponíveis, firewall, SIEM e agentes ativos, e Suricata gerando eventos."),
  figura("prints/29_ia_relatorio_saude.png", "Relatório de saúde gerado pelo ai-analyst (ia/saude.md)", 520),
  H2("Testes realizados (Fase 6)"),
  P("O Quadro 11 consolida os seis testes. Os horários, regras e análises foram extraídos automaticamente dos arquivos " +
    "de evidência."),
  tabela("Resumo dos testes no ambiente experimental",
    ["Teste", "Situação / comando", "Horário", "Esperado", "Alertas (regra, nível)", "Análise da IA / ação"],
    testes.map((t, i) => [
      `T${i + 1}`, t.meta.nome + "\n$ " + t.meta.comando, `${hora(t.meta.inicio)}–${hora(t.meta.fim)}`,
      t.meta.esperado, regras(t), analiseIA(t)]),
    [0.75, 2.6, 1.05, 2.1, 1.65, 2.45]),
);

const detalhes = [
  { n: 1, txt: "Situação hipotética: cinco alertas da regra local de varredura (sid 9100002) com origem no cliente " +
    "foram registrados. O SIEM classificou-os pela regra 100211 (nível 8, MITRE T1046 – Network Service Discovery), e a IA " +
    "classificou o incidente como suspeito, de gravidade média, recomendando monitoramento.",
    figs: [["prints/09_teste1_alertas_siem.png", "Teste 1 — alertas de varredura no SIEM (situação hipotética)"],
      ["prints/10_teste1_analise_ia.png", "Teste 1 — evidências e análise da IA"]] },
  { n: 2, txt: "Situação hipotética: quinze tentativas de login SSH falhas do cliente contra o servidor. As regras padrão " +
    "do Wazuh 5760 e 5710 (nível 5) foram geradas e a correlação por frequência disparou a regra 5763 (nível 10, T1110 – " +
    "Brute Force). Por ser a primeira ocorrência, a IA recomendou o bloqueio sem aplicá-lo e gravou os comandos de " +
    "aprovação e uma sugestão de regra de active response.",
    figs: [["prints/12_teste2_alertas_siem.png", "Teste 2 — alertas sshd e correlação 5763 (situação hipotética)"],
      ["prints/14_teste2_recomendacao_ia.png", "Teste 2 — recomendação da IA (bloqueio recomendado, não aplicado)"]] },
  { n: 3, txt: "O cliente acessou a página de teste no site fictício, que devolve o mesmo conteúdo usado pelo testmynids.org. " +
    "O Suricata real detectou a assinatura GPL ATTACK_RESPONSE id check returned root (sid 2100498), e o SIEM gerou a regra " +
    "100201 (nível 7). Como a origem é externa ao laboratório, a IA não recomendou bloqueio. Trata-se de um teste de " +
    "assinatura conhecido, portanto um positivo esperado.",
    figs: [["prints/15_teste3_terminal.png", "Teste 3 — acesso à página de teste do IDS"],
      ["prints/16_teste3_alertas_siem.png", "Teste 3 — alerta do Suricata no SIEM"]] },
  { n: 4, txt: "Foram alterados /var/www/html/index.html e criado /etc/lab-fim-teste.conf no servidor. O FIM gerou as " +
    "regras 550 (integridade alterada, nível 7, T1565.001) e 554 (arquivo adicionado, nível 5). A IA recomendou confirmar " +
    "se a mudança foi autorizada e analisar o diff.",
    figs: [["prints/19_teste4_alertas_siem.png", "Teste 4 — alertas de integridade de arquivos (FIM)"],
      ["prints/20_teste4_analise_ia.png", "Teste 4 — análise da IA para a alteração de arquivos"]] },
  { n: 5, txt: "O cliente tentou acessar cinco serviços da rede de gerência, cinco vezes cada. Todas as conexões foram " +
    "descartadas pelo firewall, que gerou 25 eventos da regra 100101 e, ao atingir 20 bloqueios em 60 segundos, a regra " +
    "100102 (nível 10, T1046). A IA classificou o incidente como de gravidade alta e recomendou o bloqueio, sem aplicá-lo.",
    figs: [["prints/21_teste5_terminal.png", "Teste 5 — tentativas de acesso à rede de gerência"],
      ["prints/22_teste5_alertas_siem.png", "Teste 5 — bloqueios do firewall e correlação 100102 no SIEM"]] },
  { n: 6, txt: "Situação hipotética: repetição do teste 2. A IA consultou a memória, encontrou dois incidentes anteriores da " +
    "mesma origem e categoria e marcou reincidência. Com AUTO_BLOCK=true, aplicou o bloqueio: o IP 192.168.10.20 entrou na " +
    "blocklist do firewall (regra 100104) e o servidor recebeu a regra iptables DROP via active response (regra 651). A " +
    "verificação confirmou o efeito: o cliente não acessou mais a internet nem o servidor, e o firewall registrou o tráfego " +
    "do IP em quarentena (regra 100103).",
    figs: [["prints/24_teste6_terminal.png", "Teste 6 — reincidência e verificação do bloqueio aplicado pela IA"],
      ["prints/27_teste6_recomendacao_ia.png", "Teste 6 — análise da IA com reincidência e bloqueio aplicado"]] },
];
for (const d of detalhes) {
  add(H3(`Teste ${d.n} — ${testes[d.n - 1].meta.nome}`), P(d.txt));
  for (const [f, l] of d.figs) add(figura(f, l, 600, 560));
}

add(H2("Visão consolidada"),
  P(`No total, o experimento gerou ${totalAlertas} alertas no formato do Wazuh (Figura ${fig + 1}). A IA registrou nove ` +
    "incidentes na memória (Figura " + (fig + 2) + "), dos quais um com reincidência e bloqueio aplicado."),
  figura("prints/31_resumo_alertas_por_regra.png", "Resumo dos alertas por regra e nível"),
  figura("prints/28_ia_historico_incidentes.png", "Histórico de incidentes mantido pela IA (ia/incidentes.md)"),
  H2("Ações extensionistas"),
  PN([HL("[Completar com os dados reais das ações extensionistas: público atendido (pequenos negócios, profissionais " +
    "autônomos, comunidade), datas e locais, questionário aplicado e principais respostas, materiais produzidos (cartilha, " +
    "apresentação, infográfico), número de participantes e registros (fotos, listas de presença). Não há dados dessas " +
    "ações nos arquivos utilizados para este relatório.]")]),
);

// VI - Discussoes
add(H1("VI – Discussões"),
  P("O Quadro 12 relaciona os objetivos específicos às evidências produzidas."),
  tabela("Cumprimento dos objetivos específicos",
    ["Objetivo", "Situação", "Evidência"],
    [["1. Laboratório virtualizado", "Atingido (implementado em Docker; demonstrado no ambiente experimental)", "docker-compose.yml; Figuras 4–6"],
     ["2. Suricata", "Atingido", "Teste 3 e Figura 9"],
     ["3. Centralização no SIEM", "Parcial: configuração do Wazuh pronta; nos testes, o SIEM foi emulado", "Regras e decoders em wazuh/config/custom; Figura 7"],
     ["4. Serviço de IA", "Parcial: pipeline, memória e prevenção funcionando; o LLM não foi executado no ambiente experimental", "Testes 1–6; ia/recomendacoes.md"],
     ["5. Testes documentados", "Atingido (com situações hipotéticas)", "testes/T1–T6.md; Quadro 11"],
     ["6. Análise dos resultados", "Atingido", "Esta seção"],
     ["7. Ações extensionistas", "A completar pelo estudante", "Seção V – Ações extensionistas"]],
    [2.6, 3.6, 3.8]),
  P("A combinação de fontes mostrou-se essencial. Cada cenário foi visto por um mecanismo diferente: a assinatura do " +
    "Suricata (teste 3), os logs de autenticação do servidor (testes 2 e 6), o FIM (teste 4) e os logs do firewall " +
    "(teste 5). Nenhuma ferramenta isolada teria coberto todos os casos, o que confirma a proposta do projeto de " +
    "centralizar as fontes no SIEM. As regras de correlação por frequência (5763 e 100102) transformaram dezenas de eventos " +
    "de baixo nível em um único alerta relevante. A triagem da IA agrupou rajadas em incidentes, chegando a nove análises " +
    `para ${totalAlertas} alertas.`),
  P("A reincidência foi o principal resultado da camada de IA. No teste 2, a IA apenas recomendou o bloqueio; no teste 6, " +
    "com o mesmo padrão vindo da mesma origem, reconheceu o histórico e aplicou a resposta. Esse comportamento conservador " +
    "reduz o risco de um falso positivo isolado interromper um serviço, mas também significa que a primeira ocorrência de " +
    "um ataque real dependeria de aprovação humana. Esse equilíbrio deve ser avaliado conforme o contexto de cada " +
    "organização."),
  P("Quanto aos falsos positivos, os alertas dos testes 3 e 4 correspondem a atividades autorizadas: a página de teste do " +
    "IDS e uma alteração planejada de arquivo. Do ponto de vista do sensor, são detecções corretas; do ponto de vista do " +
    "negócio, não são incidentes. Isso reforça a necessidade de contexto, como janelas de mudança e lista de testes " +
    "autorizados, que pode ser incorporado à memória da IA. Também se observou que o bloqueio do cliente no firewall " +
    "interrompe a comunicação do seu próprio agente com o SIEM, um efeito colateral registrado nas recomendações."),
  P("As limitações devem ser consideradas na interpretação:"),
  bullet("o SIEM foi emulado, com regras reproduzidas a partir do ruleset oficial, e não o Wazuh real;"),
  bullet("os testes 1, 2 e 6 usaram eventos hipotéticos;"),
  bullet("o LLM não foi executado, de modo que a qualidade das análises do DeepSeek-R1 ainda não foi medida;"),
  bullet("não foram calculadas métricas quantitativas (precisão, revocação) por falta de volume de tráfego real."),
  P("Esses pontos são o foco da continuidade no TCC."),
  PN([B("Desenvolvimento do estudante: "), HL("[Completar com a reflexão pessoal sobre o desenvolvimento cognitivo, " +
    "socioemocional e cultural durante o projeto: aprendizados técnicos, dificuldades enfrentadas, interação com o público " +
    "das ações extensionistas e mudanças de percepção sobre segurança digital.]")]),
);

// VII - Conclusoes
add(H1("VII – Conclusões e Recomendações Futuras"),
  P("O projeto atingiu o objetivo de construir e documentar uma arquitetura de monitoramento de redes que integra " +
    "firewall, IDS, SIEM e Inteligência Artificial. A demonstração em ambiente experimental, com situações hipotéticas, " +
    "mostrou o fluxo completo: geração do evento, detecção, correlação, análise, memória de incidentes e prevenção. A " +
    "reincidência foi reconhecida e o bloqueio foi aplicado de forma controlada. A experiência também evidenciou que a " +
    "segurança depende mais da integração e do contexto do que de uma ferramenta isolada, aprendizado que se conecta " +
    "diretamente às orientações levadas aos pequenos negócios nas ações extensionistas."),
  P("Como recomendações para trabalhos futuros, com foco no TCC:"),
  num("Executar o laboratório completo em Docker (Wazuh real e Ollama) seguindo o lab.ps1 e repetir os seis testes, comparando com os resultados deste relatório.", "num2"),
  num("Avaliar a qualidade das análises do DeepSeek-R1 e do Hermes 3 nos mesmos incidentes, que ficam salvos em ia/analises com o prompt utilizado.", "num2"),
  num("Incluir o Zeek e métodos de detecção de anomalias (por exemplo, Isolation Forest) para comparar assinaturas e comportamento, com métricas de precisão, revocação e falsos positivos.", "num2"),
  num("Incorporar contexto de negócio à memória da IA (janelas de manutenção, testes autorizados) para reduzir falsos positivos.", "num2"),
  num("Transformar os aprendizados em material de conscientização para pequenos negócios, como um guia de monitoramento básico com ferramentas gratuitas.", "num2"),
);

// VIII - Referencias
const refs = [
  "BIBLIOTECA DO IFC. Consulta ao Acervo – Normas para Elaboração de Trabalhos Acadêmicos. Disponível em: <https://biblioteca.ifc.edu.br/camboriu/>. Acesso em: 04 ago. 2026.",
  "BRASIL. Conselho Nacional de Educação. Resolução CNE/CES nº 7, de 18 de dezembro de 2018. Estabelece as Diretrizes para a Extensão na Educação Superior Brasileira. Brasília, DF: Ministério da Educação, 2018.",
  "BRASIL. Lei nº 13.709, de 14 de agosto de 2018. Lei Geral de Proteção de Dados Pessoais (LGPD). Brasília, DF: Presidência da República, 2018. Disponível em: https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm. Acesso em: 19 ago. 2026.",
  "DEBASTIANI, Carlos Alberto. Definindo escopo em projetos de software. São Paulo: Novatec, 2015.",
  "DEEPSEEK-AI. DeepSeek-R1: Incentivizing Reasoning Capability in LLMs via Reinforcement Learning. arXiv:2501.12948, 2025.",
  "HINTZBERGEN, Jule; HINTZBERGEN, Kees; SMULDERS, André; BAARS, Hans. Fundamentos de segurança da informação: com base na ISO 27001 e na ISO 27002. Rio de Janeiro: Brasport, 2018.",
  "KUROSE, James F.; ROSS, Keith W. Redes de computadores e a Internet: uma abordagem top-down. 6. ed. São Paulo: Pearson, 2013.",
  "LEWIS, Patrick et al. Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks. In: Advances in Neural Information Processing Systems (NeurIPS), 2020.",
  "MITRE. MITRE ATT&CK. Disponível em: https://attack.mitre.org/. Acesso em: 12 nov. 2026.",
  "NIST. The NIST Cybersecurity Framework (CSF) 2.0. NIST CSWP 29. Gaithersburg: National Institute of Standards and Technology, 2024.",
  "OPEN INFORMATION SECURITY FOUNDATION. Suricata User Guide: EVE JSON Output. OISF. Disponível em: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html. Acesso em: 19 ago. 2026.",
  "TANENBAUM, Andrew S. Redes de computadores. 4. ed. Rio de Janeiro: Campus, 2003.",
  "TEKNIUM, R.; QUESNELLE, J.; GUANG, C. Hermes 3 Technical Report. arXiv:2408.11857, 2024.",
  "WAZUH. Network IDS Integration: Suricata. Wazuh Documentation. Disponível em: https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html. Acesso em: 19 ago. 2026.",
  "WAZUH. Wazuh Docker deployment (single-node). Disponível em: https://documentation.wazuh.com/current/deployment-options/docker/. Acesso em: 12 nov. 2026.",
  "ZEEK PROJECT. The Zeek Network Security Monitor: Documentation. Zeek Project. Disponível em: https://docs.zeek.org/. Acesso em: 19 ago. 2026.",
];
add(H1("VIII – Referências Bibliográficas"),
  ...refs.map(r => new Paragraph({ spacing: { after: 160, line: 240 }, alignment: AlignmentType.LEFT, children: [run(r)] })));

// Apendices
add(new Paragraph({ children: [new PageBreak()] }), H1("Apêndices"), H2("Cronograma atualizado"),
  tabela("Cronograma atualizado das ações do projeto",
    ["Etapa", "Ago", "Set", "Out", "Nov", "Dez", "Situação"],
    [["1 – Revisão bibliográfica", "X", "X", "", "", "", "Concluída"],
     ["2 – Planejamento das ações extensionistas", "", "X", "X", "", "", "[confirmar]"],
     ["3 – Laboratório e monitoramento", "", "", "X", "X", "", "Concluída (implementação e ambiente experimental)"],
     ["4 – Ações e experimentos", "", "", "", "X", "", "Experimentos concluídos; ações extensionistas [confirmar]"],
     ["5 – Avaliação e documentação", "", "", "", "X", "X", "Em andamento (este relatório)"]],
    [3.4, 0.6, 0.6, 0.6, 0.6, 0.6, 3.2]),
);

// Anexos
add(H1("Anexos"),
  H2("Anexo A – Repositório"),
  PN(["Repositório do projeto (código, configurações, evidências e prints): ", "https://github.com/Macacoazul/Extensao-Universitaria-II",
    ". Pasta local: Implementacao (versionada com Git). Estrutura principal:"]),
  ...code(["docker-compose.yml  .env.example  lab.ps1  PROGRESSO.md  README.md",
    "pfsense/firewall/   firewall nftables (regras, ulogd2, rsyslog, API de bloqueio)",
    "lan/                imagem do Ubuntu Server/Cliente com agente Wazuh",
    "suricata/           entrypoint do sensor e regras locais",
    "wazuh/              Wazuh single-node oficial + decoders, regras e agent.conf do laboratório",
    "ia/                 ai-analyst (Python) e testes automatizados",
    "simulacao/          ambiente experimental (máquinas simuladas, emulador do SIEM, eventos hipotéticos)",
    "testes/  prints/  relatorio/   evidências, capturas e este relatório"]),
  new Paragraph({ spacing: { after: 120 }, children: [] }),
  H2("Anexo B – Serviços do docker-compose.yml"),
  tabela("Serviços definidos no docker-compose.yml",
    ["Serviço", "Imagem", "Rede / IP"],
    [["firewall", "lab-soc/firewall (Debian + nftables)", "wan .2 · lan .1 · mgmt .2"],
     ["server / cliente", "lab-soc/server, lab-soc/cliente (Ubuntu 24.04 + wazuh-agent)", "lan .10 / .20"],
     ["suricata", "jasonish/suricata:7.0", "host (br-lab-lan)"],
     ["wazuh.manager / indexer / dashboard", "wazuh/wazuh-*:4.14.10", "mgmt .10 / .11 / .12"],
     ["wazuh-route", "alpine:3.20 (rota de retorno para a LAN)", "namespace do manager"],
     ["ollama", "ollama/ollama", "mgmt .20"],
     ["ai-analyst", "lab-soc/ai-analyst (Python 3.12)", "mgmt .21"],
     ["prints (sob demanda)", "playwright/python", "mgmt"]],
    [2.6, 4.4, 3]),
  H2("Anexo C – Trechos das regras"),
  PN([B("Firewall (nftables) – cadeia forward:")]),
  ...code(['ip saddr @blocklist limit rate 20/second log prefix "FW-BLOCKLIST " group 1',
    "ip saddr @blocklist counter drop",
    "iifname $LAN_IF oifname $WAN_IF ip saddr $LAN_NET udp dport { 53, 123 } counter accept",
    "iifname $LAN_IF oifname $WAN_IF ip saddr $LAN_NET tcp dport { 53, 80, 443 } counter accept",
    "iifname $LAN_IF oifname $MGMT_IF ip daddr $WAZUH tcp dport { 1514, 1515 } counter accept",
    'limit rate 50/second burst 100 packets log prefix "FW-DROP " group 1',
    "counter drop"]),
  new Paragraph({ spacing: { after: 120 }, children: [] }),
  PN([B("Wazuh – regras locais (resumo):")]),
  ...code(["100101 (nível 5)  tráfego bloqueado pelo firewall (FW-DROP)",
    "100102 (nível 10) 20 bloqueios em 60 s da mesma origem (T1046)",
    "100103 (nível 7)  tráfego de IP em quarentena;  100104 (nível 8) IP bloqueado pela resposta a incidente",
    "100200/100201/100202  Suricata severidade 1/2/3 -> níveis 10/7/4",
    "100210 (nível 10) SSH múltiplas conexões (T1110);  100211 (nível 8) varredura na LAN (T1046)"]),
  new Paragraph({ spacing: { after: 120 }, children: [] }),
  H2("Anexo D – Lista de capturas (pasta prints/)"),
  ...fs.readdirSync(path.join(ROOT, "prints")).filter(f => f.endsWith(".png")).sort()
    .map(f => bullet(f)),
);

// ------------------------------------------------------------------ documento
const doc = new Document({
  creator: "Matheus Souza da Silva", title: "Checkpoint 4 – Relatório Final", description: "Extensão Universitária II",
  styles: {
    default: { document: { run: { font: FONT, size: 24 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 26, bold: true }, paragraph: { spacing: { before: 300, after: 160 }, keepNext: true, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true }, paragraph: { spacing: { before: 220, after: 120 }, keepNext: true, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true, italics: true }, paragraph: { spacing: { before: 180, after: 100 }, keepNext: true, outlineLevel: 2 } },
    ],
  },
  numbering: { config: [
    { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    { reference: "num", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    { reference: "num2", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
  ] },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
      children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
    children: C_,
  }],
});

Packer.toBuffer(doc).then(buf => {
  const out = path.join(ROOT, "relatorio", "Checkpoint4.docx");
  fs.writeFileSync(out, buf);
  console.log("gerado", out, `(${fig} figuras, ${tab} quadros)`);
});
