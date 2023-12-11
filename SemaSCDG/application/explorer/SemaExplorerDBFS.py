#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
import sys
from SemaExplorer import SemaExplorer

class SemaExplorerDBFS(SemaExplorer):
    def __init__(
        self,
        simgr,
        exp_dir,
        nameFileShort,
        scdg_graph,
        call_sim,
        config_file="config.ini"
    ):
        super(SemaExplorerDBFS, self).__init__(
            simgr,
            exp_dir,
            nameFileShort,
            scdg_graph,
            call_sim,
            config_file
        )
        self.log = logging.getLogger("SemaExplorerDBFS")
        self.log.setLevel("INFO")
        self.flag = False
        
    def manage_stashes(self, simgr):
        if self.flag:
            while simgr.active:
                simgr.stashes["pause"].append(simgr.active.pop())
           
        # If limit of simultaneous state is not reached and we have some states available in pause stash
        if len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state:
            moves = min(
                self.max_simul_state - len(simgr.active),
                len(simgr.stashes["pause"]),
            )
            if self.flag:
                for m in range(moves):
                    super().take_smallest(simgr, "pause")
            else:
                for m in range(moves):
                    super().take_longuest(simgr, "pause")
        super().manage_pause(simgr)
        
        super().drop_excessed_loop(simgr)

        # If states end with errors, it is often worth investigating. Set DEBUG_ERROR to live debug
        # TODO : add a log file if debug error is not activated
        super().manage_error(simgr)

        super().manage_unconstrained(simgr)
    

    def step(self, simgr, stash="active", **kwargs):

        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except Exception as inst:
            self.log.warning("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")
            # self.log.warning(type(inst))    # the exception instance
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.warning(exc_type, exc_obj)
            exit(-1)
        super().build_snapshot(simgr)

        if self.verbose and (len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended):
            self.log.info("A new block of execution have been executed with changes in sim_manager.")
            self.log.info("Currently, simulation manager is :\n" + str(simgr))
            self.log.info("pause stash len :" + str(len(simgr.stashes["pause"])))

        if self.verbose and len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)) + " " + hex(simgr.active[0].addr) + " " + hex(simgr.active[1].addr))
        
        c = 0
        if len(simgr.active) > 0:
            for key, symbol in simgr.active[0].solver.get_variables("buffer"):
                c += 1
        if self.flag == False and c > 0:
            self.flag = True
            simgr.stashes["uninteresting"] = simgr.stashes["pause"]
            simgr.stashes["pause"] = []
        # We detect fork for a state
        super().manage_fork(simgr)

        self.manage_stashes(simgr)

        for vis in simgr.active:
            self.dict_addr_vis.add(str(super().check_constraint(vis, vis.history.jump_target)))

        super().excessed_step_to_active(simgr)

        super().excessed_loop_to_active(simgr)

        super().time_evaluation(simgr)
       
        return simgr
