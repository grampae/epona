from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class CronArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

    async def parse_dictionary(self, dictionary_arguments):
        pass


class CronCommand(CommandBase):
    cmd = "cron"
    needs_admin = False
    help_cmd = "cron"
    description = "Enumerate cron jobs: /etc/crontab, /etc/cron.d/, periodic dirs, user crontabs, and crontab -l."
    version = 1
    author = "@grampae"
    attackmapping = ["T1053.003"]
    argument_class = CronArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = ""
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
