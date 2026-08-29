# -*- coding: utf-8 -*-
from owlready2 import *
import time
onto = get_ontology("file://"+ "/home/claude/VotingOntoSec.owl").load()

n_classes = len(list(onto.classes()))
print("Classes:", n_classes)

# Run HermiT
t0=time.time()
inconsistent=[]
try:
    with onto:
        sync_reasoner_hermit(infer_property_values=True, debug=0)
    elapsed=time.time()-t0
    consistent=True
except OwlReadyInconsistentOntologyError:
    elapsed=time.time()-t0
    consistent=False

# unsatisfiable classes = subclasses of Nothing
unsat=[c for c in onto.classes() if Nothing in c.is_a]
print("=== HermiT RESULTS ===")
print("Global consistency:", "CONSISTENT" if consistent else "INCONSISTENT")
print("Unsatisfiable (equiv to Nothing) classes:", len(unsat))
print("Classification time (s): %.3f" % elapsed)

# check for inferred equivalences / new subsumptions
eq=0
for c in onto.classes():
    for e in c.equivalent_to:
        eq+=1
print("Inferred equivalent-class axioms:", eq)

# domain/range coherence: no property whose domain/range became Nothing
incoh=0
for p in onto.object_properties():
    for d in p.domain:
        if d is Nothing: incoh+=1
    for r in p.range:
        if r is Nothing: incoh+=1
print("Object-property domain/range incoherences:", incoh)

# sample inferred property values on an individual (traceability)
vd = onto.search_one(iri="*voterData_1")
print("Sample inference - voterData_1 isHarmedBy:", [x.name for x in vd.isHarmedBy])
la = onto.search_one(iri="*lackOfAnonymity_1")
print("Sample inference - lackOfAnonymity_1 exploitedBy:", [x.name for x in la.exploitedBy])
