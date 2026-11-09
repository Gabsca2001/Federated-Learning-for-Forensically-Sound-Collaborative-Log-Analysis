"""Adapt the preserved plotting script to the new branches and burst schedules."""
from pathlib import Path
out=Path(__file__).parent
text=(out.parent/'sequential-policy-20261103/plot_online_results.py').read_text()
text=text.replace('active-sequential','active-current-evidence')
text=text.replace('Sequential current-round quarantine','Confirmed current-evidence quarantine')
old="schedule=tasks[0]['task']['attack_rounds'];ax.axvspan(min(schedule)-.4,max(schedule)+.4,color='#e2e8f0',alpha=.55)"
new="""schedule=tasks[0]['task']['attack_rounds'];bursts=[]
        for number in schedule:
            if not bursts or number!=bursts[-1][-1]+1:bursts.append([number])
            else:bursts[-1].append(number)
        for burst in bursts:ax.axvspan(burst[0]-.4,burst[-1]+.4,color='#e2e8f0',alpha=.55)"""
assert old in text;text=text.replace(old,new)
text=text.replace('Frozen online study: intervention acts on current updates only','New reserved study: confirmation for entry, current evidence for continuation')
(out/'plot_online_results.py').write_text(text)
print('CURRENT-EVIDENCE FIGURE SCRIPT PREPARED')
