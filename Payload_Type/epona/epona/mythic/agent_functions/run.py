from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RunArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="executable",
                type=ParameterType.String,
                description="Binary to execute",
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments to pass to the binary",
                parameter_group_info=[ParameterGroupInfo(required=False)],
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        parts = self.command_line.strip().split(" ", 1)
        if not parts[0]:
            raise ValueError("Must supply an executable")
        self.add_arg("executable", parts[0])
        if len(parts) > 1:
            self.add_arg("arguments", parts[1])

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run -Executable [binary] [-Arguments [args]]"
    description = "Run a binary directly (no shell wrapper) with optional arguments."
    version = 1
    author = "@grampae"
    attackmapping = ["T1106"]
    argument_class = RunArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        exe  = task.args.get_arg("executable")
        args = task.args.get_arg("arguments")
        task.display_params = f"{exe} {args}".strip()
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
