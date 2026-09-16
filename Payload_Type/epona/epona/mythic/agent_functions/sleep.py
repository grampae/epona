from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


def positive_time(val):
    if val < 0:
        raise ValueError("Value must be positive")


class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="seconds",
                type=ParameterType.Number,
                validation_func=positive_time,
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
                description="Seconds between callbacks",
            ),
            CommandParameter(
                name="jitter",
                type=ParameterType.Number,
                validation_func=positive_time,
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
                description="Jitter percentage (0-100)",
            ),
        ]

    async def parse_arguments(self):
        if self.command_line[0] != "{":
            parts = self.command_line.split()
            self.add_arg("seconds", parts[0])
            if len(parts) >= 2:
                self.add_arg("jitter", parts[1])
        else:
            self.load_args_from_json_string(self.command_line)


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep <seconds> [jitter%]"
    description = "Update sleep interval and jitter"
    version = 1
    author = "@grampae"
    attackmapping = []
    argument_class = SleepArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.MacOS, SupportedOS.Linux, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        secs = task.args.get_arg("seconds")
        jitter = task.args.get_arg("jitter")
        task.display_params = f"{secs}s jitter={jitter}%"
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
