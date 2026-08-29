# -*- coding: utf-8 -*-
"""Enriched VotingOntoSec: labels/comments, class-level semantic restrictions,
individuals with risk data; then HermiT + full metrics."""
from owlready2 import *
import json, time

onto = get_ontology("http://enu.kz/ontologies/VotingOntoSec#")

with onto:
    class Asset(Thing): pass
    class Threat(Thing): pass
    class Vulnerability(Thing): pass
    class Countermeasure(Thing): pass
    class Risk(Thing): pass
    class SecurityCriteria(Thing): pass

    sec = ["Availability","Integrity","Confidentiality","ElectionTransparency",
           "NonDiscrimination","VoterEquality","VoterPrivacy"]
    for n in sec: types.new_class(n,(SecurityCriteria,))

    class BusinessAsset(Asset): pass
    class SystemAsset(Asset): pass
    business=["BlockConfirmation","BlockGeneration","MiningProcess","DataProcessing",
      "DataValidation","TransactionValidation","Ledger","GossipingProtocol","NetworkResources",
      "DigitalAsset","KeyManagement","DataProtectionRegulation","VotingOperation","ActionLog",
      "InformationFlow","Service","Stakeholder","VotingSystem","Transaction","FastTransaction"]
    for n in business: types.new_class(n,(BusinessAsset,))
    system=["VotingData","SpecificVotingData","VoterData","Wallet","Credential","Server",
      "DeviceSetting","VotingDevice","NetworkNode","SmartContract","CommunicationChannel"]
    for n in system: types.new_class(n,(SystemAsset,))

    threats=["BlockWithholdingDelay","DataTampering","DataTheft","DeanonymizationAttack",
      "EclipseAttack","EndpointThreat","ManInTheMiddle","ReplayAttack","VoteManipulation",
      "QuantumComputingThreat","Repudiation","SinglePointFailure","SmartContractThreat",
      "SocialEngineering","SybilAttack","SybilBasedDenialOfService","TamperingDeviceSetting"]
    for n in threats: types.new_class(n,(Threat,))

    vulns=["FiftyOnePercentAttack","AcceptingUnconfirmedTransaction","DelayValidBlocksSubmission",
      "ErrorProneAuthenticityOfData","ErrorProneSmartContract","FakeIdentitiesCreation",
      "ImproperSecurityControlsForDatabase","IneffectiveCryptographicControl","IneffectiveLogging",
      "InsecureCommunicationControl","LackOfAwareness","LackOfComputingPower","LackOfVotingDataAccess",
      "NetworkAnalysis","NetworkListening","NoAnonymizationOfVoter","NoGuaranteeOfVotingRecords",
      "NoProperAuthenticationOfNode","NoQuantumSafeCryptography","NotHandlingLargeNumberOfRequestsToServer",
      "LackOfAuthentication","WeakEncryption","PoisoningNodesRoutingTable","RelyingOnCentralizedServer",
      "RelyingOnThirdParty","SybilNodesParticipateInConsensus","WeakAccessControl","WeakControlOverVotingRecord",
      "WeakControlsOnVotingDevice","WeakControlToProveDataChangesByAuthorizedUser","WeakTraceabilityControl"]
    for n in vulns: types.new_class(n,(Vulnerability,))

    cms=["HomomorphicEncryption","AnonymityOverlayNetwork","ZeroKnowledgeProof","MixNet",
      "EndToEndEncryption","TLSEncryption","MultiFactorAuthentication","ProofOfAuthority",
      "IdentityVerification","FormalVerification","SmartContractAuditing","TamperResistantDevice",
      "BlockchainBasedStorage","IntrusionDetection","WebApplicationFirewall","DDoSPreventionService",
      "PostQuantumCryptography","VoterAwarenessTraining","AnonymizationTechnology","CryptographicProtocol"]
    for n in cms: types.new_class(n,(Countermeasure,))

    for n in ["DataCompromise","LossOfPrivacy","AvailabilityAttack","TransactionManipulation"]:
        types.new_class(n,(Risk,))

    class affects(ObjectProperty):        domain=[Threat];         range=[Asset]
    class isHarmedBy(ObjectProperty):     domain=[Asset];          range=[Vulnerability]
    class exploits(ObjectProperty):       domain=[Threat];         range=[Vulnerability]
    class exploitedBy(ObjectProperty):    domain=[Vulnerability];  range=[Threat]
    class mitigatedBy(ObjectProperty):    domain=[Threat];         range=[Countermeasure]
    class mitigates(ObjectProperty):      domain=[Countermeasure]; range=[Threat]
    class reduces(ObjectProperty):        domain=[Countermeasure]; range=[Vulnerability]
    class protects(ObjectProperty):       domain=[Countermeasure]; range=[Asset]
    class hasRisk(ObjectProperty):        domain=[Asset];          range=[Risk]
    class givesRiseTo(ObjectProperty):    domain=[Vulnerability];  range=[Risk]
    class threatens(ObjectProperty):      domain=[Threat];         range=[SecurityCriteria]
    class supports(ObjectProperty):       domain=[Countermeasure]; range=[SecurityCriteria]
    class ownedBy(ObjectProperty):        domain=[Asset];          range=[Thing]
    class hasSource(ObjectProperty):      domain=[Threat];         range=[Thing]
    class requires(ObjectProperty):       domain=[Asset];          range=[SecurityCriteria]
    class dependsOn(ObjectProperty):      domain=[Asset];          range=[Asset]
    exploits.inverse_property = exploitedBy
    mitigates.inverse_property = mitigatedBy
    AllDisjoint([Asset,Threat,Vulnerability,Countermeasure,SecurityCriteria,Risk])

    class hasImpactLevel(DataProperty, FunctionalProperty):  domain=[Risk]; range=[str]
    class hasLikelihood(DataProperty, FunctionalProperty):   domain=[Risk]; range=[str]
    class hasAssetCriticality(DataProperty):                 domain=[Asset]; range=[float]
    class hasRiskScore(DataProperty):                        domain=[Risk]; range=[float]
    class hasThreatProbability(DataProperty):                domain=[Threat]; range=[float]
    class hasCVSS(DataProperty):                             domain=[Vulnerability]; range=[float]
    class hasDescription(DataProperty):                      range=[str]
    class hasIdentifier(DataProperty):                       range=[str]
    class isQuantumSafe(DataProperty):                       domain=[Countermeasure]; range=[bool]

    # ---- class-level semantic restrictions (the "backbone" relationships) ----
    Threat.is_a.append(affects.some(Asset))
    Threat.is_a.append(exploits.some(Vulnerability))
    Vulnerability.is_a.append(exploitedBy.some(Threat))
    Countermeasure.is_a.append(reduces.some(Vulnerability))
    Countermeasure.is_a.append(mitigates.some(Threat))

    # specific threat -> vulnerability and countermeasure -> vulnerability links (domain knowledge)
    def C(n): return onto[n]
    spec = [
      ("SybilAttack","exploits","SybilNodesParticipateInConsensus"),
      ("SybilAttack","exploits","FakeIdentitiesCreation"),
      ("DeanonymizationAttack","exploits","NoAnonymizationOfVoter"),
      ("ManInTheMiddle","exploits","InsecureCommunicationControl"),
      ("SmartContractThreat","exploits","ErrorProneSmartContract"),
      ("QuantumComputingThreat","exploits","NoQuantumSafeCryptography"),
      ("ReplayAttack","exploits","AcceptingUnconfirmedTransaction"),
      ("EclipseAttack","exploits","PoisoningNodesRoutingTable"),
      ("DataTampering","exploits","WeakControlOverVotingRecord"),
      ("TamperingDeviceSetting","exploits","WeakControlsOnVotingDevice"),
      ("SocialEngineering","exploits","LackOfAwareness"),
      ("SinglePointFailure","exploits","RelyingOnCentralizedServer"),
    ]
    for t,p,v in spec:
        C(t).is_a.append(getattr(onto,p).some(C(v)))
    cm_reduces = [
      ("HomomorphicEncryption","NoAnonymizationOfVoter"),
      ("AnonymityOverlayNetwork","NoAnonymizationOfVoter"),
      ("ProofOfAuthority","SybilNodesParticipateInConsensus"),
      ("IdentityVerification","FakeIdentitiesCreation"),
      ("TLSEncryption","InsecureCommunicationControl"),
      ("EndToEndEncryption","InsecureCommunicationControl"),
      ("FormalVerification","ErrorProneSmartContract"),
      ("SmartContractAuditing","ErrorProneSmartContract"),
      ("PostQuantumCryptography","NoQuantumSafeCryptography"),
      ("MultiFactorAuthentication","LackOfAuthentication"),
      ("TamperResistantDevice","WeakControlsOnVotingDevice"),
      ("VoterAwarenessTraining","LackOfAwareness"),
    ]
    for cm,v in cm_reduces:
        C(cm).is_a.append(onto.reduces.some(C(v)))

    # labels + comments (annotations) for all classes
    for c in list(onto.classes()):
        c.label = [c.name]
        c.comment = ["VotingOntoSec concept: %s" % c.name]

    # ---- individuals (extended multi-asset scenario) with risk data ----
    chains=[
      ("VoterData","voterData_1","NoAnonymizationOfVoter","lackOfAnonymity_1","DeanonymizationAttack","deanon_1","HomomorphicEncryption","homomorphicEnc_1","LossOfPrivacy","riskPrivacy_1","Medium","High",0.60,0.80,0.70),
      ("SmartContract","smartContract_1","ErrorProneSmartContract","errProneSC_1","SmartContractThreat","scThreat_1","FormalVerification","formalVer_1","DataCompromise","riskSC_1","Medium","High",0.65,0.85,0.75),
      ("NetworkNode","consensusNode_1","FakeIdentitiesCreation","fakeIdent_1","SybilAttack","sybil_1","ProofOfAuthority","poa_1","AvailabilityAttack","riskSybil_1","High","High",0.75,0.95,0.85),
      ("CommunicationChannel","channel_1","InsecureCommunicationControl","insecureComm_1","ManInTheMiddle","mitm_1","TLSEncryption","tls_1","DataCompromise","riskMitm_1","High","High",0.80,1.00,0.90),
      ("VotingDevice","device_1","WeakControlsOnVotingDevice","weakCtrl_1","TamperingDeviceSetting","tamper_1","TamperResistantDevice","tamperResist_1","TransactionManipulation","riskDev_1","Medium","Medium",0.70,0.90,0.80),
    ]
    for ac,ai,vc,vi,tc,ti,cc,ci,rc,ri,lik,imp,P,Cc,R in chains:
        a=getattr(onto,ac)(ai); v=getattr(onto,vc)(vi); t=getattr(onto,tc)(ti)
        cm=getattr(onto,cc)(ci); rk=getattr(onto,rc)(ri)
        a.isHarmedBy.append(v); v.exploitedBy.append(t); t.affects.append(a); t.exploits.append(v)
        t.mitigatedBy.append(cm); cm.reduces.append(v); cm.protects.append(a)
        a.hasRisk.append(rk); v.givesRiseTo.append(rk)
        rk.hasImpactLevel=imp; rk.hasLikelihood=lik
        a.hasAssetCriticality.append(Cc); t.hasThreatProbability.append(P); rk.hasRiskScore.append(R)

onto.save(file="VotingOntoSec.owl", format="rdfxml")

# ---- run HermiT ----
t0=time.time(); consistent=True
try:
    with onto: sync_reasoner_hermit(infer_property_values=True, debug=0)
except OwlReadyInconsistentOntologyError:
    consistent=False
elapsed=time.time()-t0
unsat=[c for c in onto.classes() if Nothing in c.is_a]

# ---- metrics ----
classes=list(onto.classes()); 
n_classes=len(classes); n_obj=len(list(onto.object_properties()))
n_data=len(list(onto.data_properties())); n_ind=len(list(onto.individuals()))

# hierarchy depth/breadth
import collections
parents={c:[p for p in c.is_a if p in classes] for c in classes}
roots=[c for c in classes if not parents[c]]           # direct subclasses of Thing
children=collections.defaultdict(list)
for c in classes:
    for p in parents[c]: children[p].append(c)
leaves=[c for c in classes if not children[c]]
depth={}
def dep(c):
    if c in depth: return depth[c]
    if not parents[c]: depth[c]=1; return 1
    depth[c]=1+max(dep(p) for p in parents[c]); return depth[c]
for c in classes: dep(c)
maxdepth=max(depth.values()); avgdepth=sum(depth.values())/len(depth)
level=collections.Counter(depth.values()); maxbreadth=max(level.values())
mult_inh=sum(1 for c in classes if len(parents[c])>1)

metrics=dict(consistent=consistent, unsat=len(unsat), time=round(elapsed,2),
  classes=n_classes, obj=n_obj, data=n_data, individuals=n_ind,
  roots=len(roots), leaves=len(leaves), maxdepth=maxdepth,
  avgdepth=round(avgdepth,2), maxbreadth=maxbreadth, mult_inh=mult_inh)
print("METRICS_JSON="+json.dumps(metrics))
