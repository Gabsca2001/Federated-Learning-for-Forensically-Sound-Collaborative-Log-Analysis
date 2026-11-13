"""Research-only objective arithmetic and deterministic full-batch gradients."""
import math

def target_distributions(counts,weights):
    if not counts or not weights:raise ValueError('empty counts or weights')
    classes=sorted(weights)
    weights={c:float(weights[c]) for c in classes}
    if any(not math.isfinite(v) or v<=0 for v in weights.values()):raise ValueError('invalid class weight')
    if any(set(v)!=set(classes) or any(type(n) is not int or n<0 for n in v.values()) or sum(v.values())==0 for v in counts.values()):
        raise ValueError('invalid class counts')
    total=sum(sum(v.values()) for v in counts.values())
    pooled={c:sum(v[c] for v in counts.values())*weights[c] for c in classes}
    mass=sum(pooled.values())
    pooled={c:v/mass for c,v in pooled.items()}
    mixture={c:0. for c in classes}
    for v in counts.values():
        client_mass=sum(v.values())/total;denom=sum(v[c]*weights[c] for c in classes)
        for c in classes:mixture[c]+=client_mass*v[c]*weights[c]/denom
    return pooled,mixture

def matched_root_weights(target,root_counts):
    if set(target)!=set(root_counts) or any(type(n) is not int or n<=0 for n in root_counts.values()):raise ValueError('missing root class')
    if any(not math.isfinite(v) or v<0 for v in target.values()) or abs(sum(target.values())-1)>1e-10:raise ValueError('invalid target')
    size=sum(root_counts.values())
    return {c:target[c]/(root_counts[c]/size) for c in target}

def loss_gradient(model,features,labels,class_weights,torch):
    model.eval()
    loss=torch.nn.functional.cross_entropy(model(features),labels,weight=class_weights,reduction='mean')
    values=torch.autograd.grad(loss,tuple(model.parameters()))
    return [v.detach().cpu().numpy().copy() for v in values],float(loss.detach())
