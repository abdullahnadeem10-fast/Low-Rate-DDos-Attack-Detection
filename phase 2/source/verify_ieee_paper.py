"""Extract and render the compiled LaTeX paper for structural and visual review."""
from pathlib import Path
import json, re
from pypdf import PdfReader
import pypdfium2 as pdfium
from PIL import Image, ImageOps, ImageDraw

root=Path(__file__).resolve().parents[2]
pdf=root/'phase 2/CNET_Phase2_IEEE.pdf'
dest=root/'tmp/phase2/ieee_render'
dest.mkdir(parents=True,exist_ok=True)
reader=PdfReader(pdf)
texts=[p.extract_text() or '' for p in reader.pages]
full='\n'.join(texts)
(dest/'extracted.txt').write_text(full,encoding='utf-8')
missing=[f'Step {i}' for i in range(1,13) if not re.search(rf'Step\s+{i}\b',full)]
assert not missing,missing
assert all(re.search(rf'\[{i}\]', full) for i in range(1,19)), 'Missing bibliography entry'
assert 'RESEARCHMETHODOLOGYARCHITECTURE' in re.sub(r'\s+','',full).upper()
assert not any(x in full for x in ['PLACEHOLDER','turn19','turn20','??'])
assert not re.search(r'\[\s*\?\s*\]',full), 'Unresolved citation in PDF'
source=(root/'phase 2/CNET_Phase2_IEEE.tex').read_text(encoding='utf-8')
assert re.findall(r'\\bibitem\{ref(\d+)\}',source)==[str(i) for i in range(1,19)]
pages=pdfium.PdfDocument(pdf)
thumbs=[]
for i,page in enumerate(pages):
    image=page.render(scale=1.7).to_pil().convert('RGB')
    image.save(dest/f'page-{i+1}.png')
    thumb=ImageOps.contain(image,(306,420))
    canvas=Image.new('RGB',(330,455),'#ddd')
    canvas.paste(thumb,((330-thumb.width)//2,10))
    ImageDraw.Draw(canvas).text((12,436),f'Page {i+1}',fill='black')
    thumbs.append(canvas)
cols=3; rows=(len(thumbs)+cols-1)//cols
sheet=Image.new('RGB',(cols*330,rows*455),'white')
for i,t in enumerate(thumbs): sheet.paste(t,((i%cols)*330,(i//cols)*455))
sheet.save(dest/'overview.png')
report={'page_count':len(reader.pages),'bytes':pdf.stat().st_size,
        'characters_per_page':[len(t) for t in texts],
        'links':sum(len(p['/Annots']) if '/Annots' in p else 0 for p in reader.pages),
        'steps_found':12,'references_found':18}
(dest/'qa.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
