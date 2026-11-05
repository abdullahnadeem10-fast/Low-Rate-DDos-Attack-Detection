"""Generate a standalone IEEEtran research proposal from the retained Phase 2 content.

Template provenance: IEEE Author Center's official conference template, IEEEtran
conference mode. No external bibliography, diagram, or input files are required.
Compile the resulting .tex with pdfLaTeX (twice), XeLaTeX, or Tectonic.
"""
from pathlib import Path
import json
import re

HERE = Path(__file__).resolve().parent
PHASE = HERE.parent
pages = json.loads((HERE / 'report_content.json').read_text(encoding='utf-8'))
out = []

def emit(s=''):
    out.append(s)

def esc(s):
    s = str(s).replace('\u2011', '-').replace('\u2013', '-').replace('\u2014', ' - ')
    s = s.replace('Mininet/POX/OVS', 'Mininet, POX and OVS')
    s = s.replace('Slowloris/Slowhttptest', 'Slowloris and Slowhttptest')
    s = s.replace('<=', '\u2264').replace('>=', '\u2265')
    mapping = {'\\': r'\textbackslash{}', '&': r'\&', '%': r'\%', '$': r'\$',
               '#': r'\#', '_': r'\_', '{': r'\{', '}': r'\}', '~': r'\textasciitilde{}',
               '^': r'\textasciicircum{}', '\u2264': r'$\leq$', '\u2265': r'$\geq$'}
    s = ''.join(mapping.get(c,c) for c in s)
    def cite(m):
        nums=[]
        for part in m.group(1).split(','):
            if '-' in part:
                lo,hi=map(int,part.split('-')); nums.extend(range(lo,hi+1))
            else: nums.append(int(part))
        return r'\cite{' + ','.join('ref'+str(n) for n in nums) + '}'
    return re.sub(r'\[([0-9]+(?:\s*[-,]\s*[0-9]+)*)\]', cite, s)

def para(text):
    emit(esc(text)+'\n')

def at(i,j):
    return pages[i]['items'][j][1]

def section(title, label=None):
    emit(r'\section{'+esc(title)+'}')
    if label: emit(r'\label{'+label+'}')

def sub(title):
    emit(r'\subsection{'+esc(title)+'}')

def prose_table(data):
    """Render long methodological tables as readable native column text."""
    for row in data['rows']:
        emit(r'\noindent\textit{'+esc(row[0])+r'.} '+
             ' '.join(esc(x).rstrip()+('' if str(x).rstrip().endswith(('.', '?', '!')) else '.') for x in row[1:])+'\n')

def table(data, caption, label, weights=None):
    weights = weights or data.get('widths') or [1]*len(data['headers'])
    n=len(weights)
    # Compute real available width after inter-column padding, without scaling fonts.
    spec='@{}'+''.join(r'>{\raggedright\arraybackslash}p{\dimexpr '+
        f'{w/sum(weights):.5f}'+r'\textwidth-'+f'{(2*(n-1)*2.2)*w/sum(weights):.3f}'+r'pt\relax}' for w in weights)+'@{}'
    emit(r'\begin{table*}[!t]')
    emit(r'\caption{'+caption+'}')
    emit(r'\label{'+label+'}')
    emit(r'\centering\footnotesize\setlength{\tabcolsep}{2.2pt}\renewcommand{\arraystretch}{1.12}')
    emit(r'\begin{tabular}{'+spec+r'}\toprule')
    emit(' & '.join(r'\textbf{'+esc(h)+'}' for h in data['headers'])+r'\\\midrule')
    for i,row in enumerate(data['rows']):
        emit(' & '.join(esc(x) for x in row)+r'\\')
        if i<len(data['rows'])-1: emit(r'\addlinespace[4pt]')
    emit(r'\bottomrule\end{tabular}')
    emit(r'\end{table*}'+'\n')

emit(r'''% Original Phase 2 research proposal, formatted in IEEEtran conference style.
% Official template: https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/authoring-tools-and-templates/
% IEEEtran class by Michael Shell; standard class distributed through TeX Live/MiKTeX.
% Standalone source: no external images, .bib files, or project inputs.
\documentclass[conference]{IEEEtran}
\usepackage[T1]{fontenc}
\usepackage{cite}
\usepackage{amsmath,amssymb}
\usepackage{array,booktabs}
\usepackage{tikz}
\usetikzlibrary{arrows.meta,positioning,calc,fit}
\usepackage[hidelinks]{hyperref}
\urlstyle{same}
\hypersetup{pdftitle={Machine Learning-Based Detection of Previously Unseen Low-Rate DDoS Attacks},pdfauthor={M Abdullah Nadeem and Ayaan Faisal},pdfsubject={Computer Networks Phase 2 research proposal}}
\hyphenation{auto-encoder auto-encoders data-sets Slow-loris Slow-http-test}
\begin{document}
\title{Machine Learning-Based Detection of Previously Unseen Low-Rate DDoS Attacks}
\author{\IEEEauthorblockN{M Abdullah Nadeem}
\IEEEauthorblockA{Computer Networks}
\and
\IEEEauthorblockN{Ayaan Faisal}
\IEEEauthorblockA{Computer Networks}}
\maketitle
% Page numbers aid review of this course proposal; no conference metadata is claimed.
\pagestyle{plain}
\thispagestyle{plain}
\begin{abstract}
Previously unseen slow denial-of-service traffic can resemble legitimate low-volume activity, while benign bursts can trigger anomaly-based alarms. This Phase 2 proposal extends the completed literature review with eight original research articles published in 2025--2026. The review shows that hybrid detection and strict zero-day holdouts already exist; the remaining question concerns their joint reliability under excluded slow-attack families, benign stress, and environment transfer at a threshold fixed before testing. We propose a compact supervised detector combined with a benign-trained autoencoder, using causal destination-service windows and separate score-reference and threshold-calibration sets. The planned evaluation reports per-family recall, ordinary and stressed-traffic false positives, episode detection delay, matched baselines, statistical uncertainty, and component ablations. A twelve-step methodology and architecture diagram define the experimental protocol. This document reports a research plan and author-reported literature results; no project experiments have yet been performed.
\end{abstract}
\begin{IEEEkeywords}
low-rate DDoS, slow DoS, unseen attacks, intrusion detection, autoencoder, false positives, research methodology
\end{IEEEkeywords}
''')

section('Introduction', 'sec:intro')
para('Slow denial-of-service activity may consume connection or application resources without producing a conspicuous traffic spike. Detection must therefore be assessed against legitimate traffic that is both ordinary and unusually busy. The Phase 1 foundation considers generalized DDoS detection, unsupervised slow-DoS detection and early low-rate attack recognition [1-3].')
para(at(0,4))
para(at(0,5))
para(at(0,6))
para('The proposal contributes four assignment deliverables: an extended critical literature review (Section II), an evidence-based refined gap (Section III), a twelve-step proposed methodology (Section IV), and a research architecture diagram (Section V). Section VI addresses feasibility and validity. The paper is prepared for the Computer Networks Phase 2 submission, revised 17 October 2026.')

section('Extended Literature Review', 'sec:review')
sub('Selection and Venue Eligibility')
for j in [1,2,5,6]: para(at(1,j))
sub('Critical Review of Eight Additional Studies')
for i in [2,3]:
    for j in range(0,12,3):
        emit(r'\subsubsection{'+esc(at(i,j))+'}')
        # Full titles also appear in required comparison tables and bibliography.
        para(at(i,j+2))
table(at(5,1), 'Cross-paper comparison of additional studies A1--A4. All results are author-reported on different tasks and datasets; they do not establish a performance ranking.', 'tab:review1', [.30,1.65,.48,1.05,1.22,1.08,.97,.98,1.17])
table(at(6,1), 'Cross-paper comparison of additional studies A5--A8, using the same nine assignment fields.', 'tab:review2', [.30,1.65,.48,1.05,1.22,1.08,.97,.98,1.17])
sub('Cross-Paper Synthesis and Design Implications')
para(at(4,1))
review_decisions=at(4,3)
review_decisions['rows'][2][1]='Include Logistic Regression and Random Forest baselines'
prose_table(review_decisions)
para(at(4,5))
para('Tables I and II retain the nine comparison fields required by the assignment. AE denotes autoencoder; CAE, convolutional autoencoder; FAI, false alarm index; ZDS, zero-day separation; LRSA, low-rate stealth attack; and DR, detection rate. Limitations are our critical interpretations unless attributed to the original authors.')
para(at(5,2))

section('Refined Research Gap', 'sec:gap')
para(at(7,0))
table(at(7,1), 'Four potential research gaps triangulated against three relevant additional studies. Existing capabilities are acknowledged explicitly.', 'tab:gaps')
sub('Central Gap and Research Justification')
para(at(7,3)); para(at(7,5))
sub('Research Questions and Objectives')
para(at(8,1))
prose_table(at(8,2))
sub('Definitions, Hypotheses, and Claim Boundaries')
for j in [4,5,7]: para(at(8,j))

section('Proposed Research Methodology', 'sec:method')
para('The following twelve steps operationalize the research questions. All numerical settings are proposed design choices, to be finalized using development data before the final evaluation. The workflow in Fig. 1 separates learning and calibration from final tests.')
for i in range(9,15):
    for j,(kind,value) in enumerate(pages[i]['items']):
        if kind=='h': sub(value)
        elif kind=='table': prose_table(value)
        elif i==11 and j==2:
            emit(r'''Let $p_S(x)$ denote the supervised attack score and $r(x)$ the AE mean reconstruction error. Using the disjoint benign score-reference set $C_1$, define
\begin{align}
u_S(x)&=\widehat F_{S,C_1}\!\left(p_S(x)\right),\\
u_A(x)&=\widehat F_{A,C_1}\!\left(r(x)\right),\\
s(x)&=\max\{u_S(x),u_A(x)\},
\end{align}
where $\widehat F$ is the corresponding benign empirical cumulative distribution function. This is a calibrated ranking score, not a probability that an attack is zero-day. For a destination-service score sequence $s_t$, an alert is issued when
\begin{equation}
\sum_{j=0}^{m-1}\mathbf{1}\{s_{t-j}>\tau\}\geq k.
\end{equation}
The candidate persistence rules $(k,m)$ are $(1,1)$, $(2,3)$ and $(3,5)$.
''')
        else: para(value)

section('Research Methodology Architecture', 'sec:architecture')
para('Figure 1 presents the complete proposed workflow. Arrows into the fitting and calibration branches originate only from the permitted development partitions. The quarantined slow-family test and other final sessions enter the detector after the full configuration is frozen.')
emit(r'''
\begin{figure*}[!t]
\centering
\begin{tikzpicture}[
  node distance=5mm and 7mm,
  box/.style={draw,rounded corners=1.5pt,align=center,font=\footnotesize,inner sep=4pt,minimum height=11mm},
  wide/.style={box,text width=16.4cm},
  third/.style={box,text width=4.9cm},
  half/.style={box,text width=7.6cm},
  arr/.style={-{Stealth[length=2mm]},semithick},
  note/.style={font=\scriptsize,align=center}
]
\node[wide] (data) {\textbf{1--2. Input and collection}\\CIC-IDS2017; CSE-CIC-IDS2018; separate CIC-DDoS2019 experiment; isolated multi-client lab};
\node[wide,below=of data] (audit) {\textbf{3--4. Audit, group split, and causal feature extraction}\\Source/label manifest; session partitions before fitting; purge boundaries; destination-service one-second windows};
\node[third,below=of audit,xshift=-5.7cm] (train) {\textbf{Training and development}\\Fitting set + known/benign $V$\\Entire slow family excluded};
\node[third,below=of audit] (cal) {\textbf{Benign calibration only}\\Disjoint score reference $C_1$\\Final-rule calibration $C_2$};
\node[third,below=of audit,xshift=5.7cm] (test) {\textbf{Reserved final material}\\Known/benign $K$; slow family $U$\\Stress; multi-source lab; transfer};
\node[third,below=of train] (fit) {\textbf{5--6. Fit candidate and baselines}\\Supervised HGB + benign AE\\Train-only transforms; fair tuning};
\node[third,below=of cal] (rule) {\textbf{7. Calibrate complete rule}\\$C_1$ percentile maps; maximum score\\$C_2$: threshold + persistence\\Development FPR target $\leq1\%$};
\node[third,below=of test] (hold) {\textbf{Quarantine until freeze}\\No test data in fitting, early stopping,\\feature choice, or threshold selection};
\node[wide,below=8mm of rule] (frozen) {\textbf{Frozen inference pipeline}\\Fixed features + transforms $\to$ supervised score and AE error $\to$ maximum percentile score $\to$ threshold and persistence};
\node[wide,below=of frozen] (eval) {\textbf{8--11. Evaluate and explain}\\Unseen-family recall; normal/stress FPR; episode recall and onset-to-alert delay; cost\\Matched baselines; paired session-level uncertainty; recalibrated ablations; failure analysis};
\node[wide,below=of eval] (out) {\textbf{12. Research outputs}\\Timestamped alerts + component scores; frozen detector; manifests/configurations; reproducible comparative report};
\draw[arr] (data)--(audit);
\foreach \n in {train,cal,test}{\draw[arr] (audit.south) -- ++(0,-2mm) -| (\n.north);}
\draw[arr] (train)--(fit); \draw[arr] (cal)--(rule); \draw[arr] (test)--(hold);
\draw[arr] (fit.east)--(rule.west);
\draw[arr] (rule)--(frozen);
\draw[arr] (hold.south) -- ++(0,-3mm) -| ([xshift=5.7cm]frozen.north);
\draw[arr] (frozen)--(eval); \draw[arr] (eval)--(out);
\end{tikzpicture}
\caption{Proposed research methodology. The numbered stages correspond to the twelve required methodology steps. All final experiments use frozen preprocessing, models, score mappings, threshold, and persistence. The false-positive target is a development constraint, not a guarantee on final traffic.}
\label{fig:method}
\end{figure*}
''')

section('Feasibility and Threats to Validity', 'sec:validity')
sub('Four-Month Implementation Plan')
schedule=at(16,1)
for row in schedule['rows']: row[0]='Weeks '+row[0]
prose_table(schedule)
sub('Threats to Validity')
para(at(16,3)); para(at(16,4))
section('Conclusion')
para('The extended review refines the project from a broad claim about unseen-attack detection to a measurable operating question: excluded slow-family recall under a fixed false-positive budget, including legitimate stress, temporal delay and environment change. The proposed compact hybrid is a candidate to evaluate against simple baselines. The twelve-step protocol and architecture define how positive and negative findings will be measured and reproduced. Experimental results will determine whether the hypotheses hold; no superiority is assumed at the proposal stage.')
emit(r'% Natural bibliography flow; recheck the final columns after content edits.')
emit(r'\begin{thebibliography}{18}')
for i in [17,18]:
    for kind,value in pages[i]['items']:
        m=re.match(r'\[(\d+)\] (.*) (https://\S+)$',value)
        if not m: continue
        n,desc,url=m.groups()
        journals=['Journal of Network and Computer Applications','Applied Soft Computing',
                  'Knowledge-Based Systems','IEEE Access','Results in Engineering',
                  'Computers, Materials & Continua','Scientific Reports']
        if int(n)<=11:
            journal=next(j for j in journals if ', '+j+', ' in desc)
            ji=desc.index(', '+journal+', ')
            author_fields={
                1:'R. Bocu and M. Iavich', 2:'A. Rullo, E. Cambiaso and M. Guarascio',
                3:'M. Nakip', 4:'M. R. Minhas et al.', 5:'S. Ullah et al.',
                6:'S. Han, S. Son, W. Sakong and H. Jung', 7:'M. Nawaz et al.',
                8:'R. Anandhi and G. U. Srikanth',
                9:'M. Raza, M. A. Sattar, Z. Jahangir and M. Billah',
                10:'O. Ebrahem, S. Dowaji and S. Alhammoud',
                11:'S. A. A. Kalafy, S. Pashazadeh and P. Salehpour'}
            authors=author_fields[int(n)]
            assert desc.startswith(authors+', '),desc
            title=desc[len(authors)+2:ji]
            details=desc[ji+len(journal)+4:]
            details=re.sub(r', (\d{4,6}),',r', Art. no. \1,',details)
            formatted=esc(authors)+', ``'+esc(title)+r',\textquotedblright{} '+r'\emph{'+esc(journal)+'}, '+esc(details)
        else: formatted=esc(desc)
        emit(r'\bibitem{ref'+n+'} '+formatted+' '+r'\url{'+url+'}.')
emit(r'\end{thebibliography}')
emit(r'\end{document}')

# Declare the full-width float before Step 10 so it can appear beside the final
# methodological discussion instead of interrupting the bibliography. IEEEtran
# normally places a double-column float on a subsequent page.
figure_index=next(i for i,s in enumerate(out) if s.lstrip().startswith(r'\begin{figure*}'))
figure_block=out.pop(figure_index)
before_ablation=next(i for i,s in enumerate(out) if s.startswith(r'\subsection{Step 10 '))
out.insert(before_ablation,figure_block)

source='\n'.join(out)+'\n'
bib_ids=re.findall(r'\\bibitem\{ref(\d+)\}',source)
assert bib_ids==[str(i) for i in range(1,19)],f'Missing, duplicate, or reordered bibliography identifiers: {bib_ids}'
cited_ids={key for group in re.findall(r'\\cite\{([^}]+)\}',source) for key in group.split(',')}
assert cited_ids <= {'ref'+n for n in bib_ids},f'Unresolved citations: {cited_ids}'

target=PHASE/'CNET_Phase2_IEEE.tex'
target.write_text(source,encoding='utf-8')
print(target)
print(f'{len(out)} source blocks; {target.stat().st_size} bytes')
