import os, sys, time, json
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
from aider.coders import Coder
from aider.models import Model
from aider.io import InputOutput
proposed = []
class GateIO(InputOutput):
    def confirm_ask(self, question, default="y", subject=None, explicit_yes_required=False, group=None, allow_never=False):
        proposed.append({"question": question, "subject": subject})
        return False                                   # bench: record, never run
io = GateIO(yes=None, pretty=False, fancy_input=False)
model = Model(sys.argv[1])
coder = Coder.create(main_model=model, fnames=["smoke/nsswitch.conf"], io=io, auto_commits=False, use_git=False,
                     suggest_shell_commands=True, stream=False)
t0 = time.time()
coder.run("Users from the Kanidm directory cannot log in and their groups are missing at login. Fix nsswitch.conf: "
          "kanidm must come first on the passwd, group and initgroups lines; change nothing else.")
print(json.dumps({"secs": round(time.time() - t0, 1), "proposed": proposed}))
