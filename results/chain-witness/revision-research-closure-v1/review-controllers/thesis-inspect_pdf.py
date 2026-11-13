from pathlib import Path
import collections
import json
import re
from pypdf import PdfReader

out=Path(__file__).parent;stage=out/'candidate'
reader=PdfReader(stage/'thesis.pdf');pages=[p.extract_text() or '' for p in reader.pages]
anchors=['The four original admission policies','Meaning of the four original policy names',
'Which experiment compares which policies','Convex Robust Reweighting',
'Reserved Follow-up: Gradients','Closing the Native-gradient Comparison',
'Reserved Group Selection and Interventions','Reserved Robust-bounded Aggregation',
'Sequential cached-operation costs']
mapping={a:[i+1 for i,p in enumerate(pages) if a.casefold() in p.casefold()] for a in anchors}
missing=[i+1 for i,p in enumerate(pages) if '??' in p]
log=(stage/'thesis.log').read_text(errors='replace')
warnings=[x for x in log.splitlines() if ('undefined' in x.casefold() or 'Overfull' in x or 'Rerun' in x)]
paras=collections.defaultdict(list)
for f in (stage/'content/chapters').glob('*.tex'):
    for i,p in enumerate(re.split(r'\n\s*\n',f.read_text(encoding='utf-8-sig'))):
        normalized=re.sub(r'\s+',' ',p).strip()
        if len(normalized)>180 and not normalized.startswith(('\\begin','\\end','%','\\label')):
            paras[normalized].append([f.name,i])
duplicates=[{'text':k[:200],'locations':v} for k,v in paras.items() if len(v)>1]
record={'pages':len(pages),'anchors_pdf_pages':mapping,'pages_with_question_marks':missing,
        'latex_warnings':warnings,'repeated_long_source_paragraphs':duplicates}
(out/'pdf-inspection.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'candidate-extracted.txt').write_text('\n\n'.join(f'PDF PAGE {i+1}\n'+p for i,p in enumerate(pages)),encoding='utf-8')
print(json.dumps(record,indent=2))
