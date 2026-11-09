"""Descriptive decomposition of a frozen selector; no new selection rule."""
import numpy as np
from retrospective_anomaly_groups import FEATURES,observations,scores


def active_intervals(flags):
    result=[];start=None
    for number,active in enumerate([*flags,False],1):
        if active and start is None:start=number
        if not active and start is not None:result.append([start,number-1]);start=None
    return result


def decompose(frames,reference,calibration):
    clients,x=observations(frames);_,expected=scores(frames,reference);tau=calibration['persistent_score_threshold']
    channels=[]
    for k,name in enumerate(FEATURES):
        c=reference['channels'][name];channels.append(np.maximum(0.,(x[:,:,k]-c['center'])/c['scale']))
    z_norm,z_validation=channels;combined=np.maximum(z_norm,z_validation)
    np.testing.assert_allclose(combined,expected,rtol=0,atol=1e-12)
    rows=[];summaries=[]
    for i,client in enumerate(clients):
        ordered=sorted(float(v) for v in combined[:,i]);persistent=(ordered[4]+ordered[5])/2
        for t in range(10):
            raw=frames[t]['indicators'][i]
            norm=float(z_norm[t,i]);validation=float(z_validation[t,i]);value=float(combined[t,i])
            rows.append(dict(client=client,round=t+1,delta_l2=raw['delta_l2'],relative_norm=raw['relative_norm'],
                log_relative_norm=float(x[t,i,0]),validation_impact=raw['validation_impact'],
                z_norm=norm,z_validation=validation,score=value,active=value>tau,
                norm_exceeds=norm>tau,validation_exceeds=validation>tau,
                dominant_channel='tie' if norm==validation else 'norm' if norm>validation else 'validation'))
        summaries.append(dict(client=client,persistent_score=persistent,anomalous=persistent>tau,
            median_norm_score=float(np.median(z_norm[:,i])),median_validation_score=float(np.median(z_validation[:,i])),
            fifth_order_score=ordered[4],sixth_order_score=ordered[5],threshold=tau,
            norm_exceedance_rounds=[t+1 for t in range(10) if z_norm[t,i]>tau],
            validation_exceedance_rounds=[t+1 for t in range(10) if z_validation[t,i]>tau],
            active_rounds=[t+1 for t in range(10) if combined[t,i]>tau],
            active_intervals=active_intervals([bool(v>tau) for v in combined[:,i]])))
    return dict(rows=rows,clients=summaries)


def confusion_metrics(cm):
    cm=np.asarray(cm,dtype=float)
    if cm.ndim!=2 or cm.shape[0]!=cm.shape[1] or (cm<0).any() or cm.sum()<=0:raise ValueError('invalid confusion matrix')
    per=[]
    for i in range(len(cm)):
        den=float(cm[i].sum()+cm[:,i].sum());per.append(2*float(cm[i,i])/den if den else 0.)
    return dict(accuracy=float(np.trace(cm)/cm.sum()),macro_f1=float(np.mean(per)),class_f1=per,
        supports=cm.sum(axis=1).astype(int).tolist())


def class_effect(before,after):
    a=confusion_metrics(before);b=confusion_metrics(after)
    if a['supports']!=b['supports']:raise ValueError('changed evaluation population')
    changes=[y-x for x,y in zip(a['class_f1'],b['class_f1'],strict=True)]
    assert abs(sum(changes)/len(changes)-(b['macro_f1']-a['macro_f1']))<1e-12
    return dict(class_f1_changes=changes,supports=a['supports'],accuracy_change=b['accuracy']-a['accuracy'],
        macro_f1_change=b['macro_f1']-a['macro_f1'])
