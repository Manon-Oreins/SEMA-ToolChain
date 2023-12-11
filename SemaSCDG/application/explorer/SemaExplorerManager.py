from explorer.SemaExplorerDFS import SemaExplorerDFS
from explorer.SemaExplorerCDFS import SemaExplorerCDFS
from explorer.SemaExplorerBFS import SemaExplorerBFS
from explorer.SemaExplorerCBFS import SemaExplorerCBFS
from explorer.SemaExplorerSDFS import SemaExplorerSDFS
from explorer.SemaExplorerDBFS import SemaExplorerDBFS
from explorer.SemaExplorerAnotherCDFS import SemaExplorerAnotherCDFS

class SemaExplorerManager():

    def __init__(self,config_file="config.ini"):
        self.expl_tech = None
        self.config_file = config_file

    def get_exploration_tech(self, nameFileShort, simgr, exp_dir, proj, expl_tech, scdg_graph, call_sim):
        self.expl_tech = SemaExplorerDFS(
            simgr, exp_dir, nameFileShort, scdg_graph, call_sim, self.config_file
        )
        if expl_tech == "CDFS":
            self.expl_tech = SemaExplorerCDFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim, self.config_file
            )
        elif expl_tech == "CBFS":
            self.expl_tech = SemaExplorerCBFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim, self.config_file
            )
        elif expl_tech == "BFS":
            self.expl_tech = SemaExplorerBFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim, self.config_file
            )
        elif expl_tech == "SCDFS":
            self.expl_tech = SemaExplorerAnotherCDFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim, self.config_file
            )
        elif expl_tech == "DBFS":
            self.expl_tech = SemaExplorerDBFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim, self.config_file
            )
        elif expl_tech == "SDFS":
            self.expl_tech = SemaExplorerSDFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim, self.config_file, proj
            )
            
        return self.expl_tech