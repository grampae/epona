from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class JobkillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="id",
                type=ParameterType.Number,
                description="Job ID to cancel (from 'jobs' output)",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply a job ID")
        self.add_arg("id", int(self.command_line.strip()))

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class JobkillCommand(CommandBase):
    cmd = "jobkill"
    needs_admin = False
    help_cmd = "jobkill <id>"
    description = "Cancel a running background job by its ID"
    version = 1
    author = "@grampae"
    attackmapping = ["T1057"]
    argument_class = JobkillArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = str(task.args.get_arg("id"))
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
