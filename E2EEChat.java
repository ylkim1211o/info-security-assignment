import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Scanner;
import java.util.Set;

public class E2EEChat {

	private Socket clientSocket = null;

	public DH dh = new DH();
	public Aes aes;
	private MessageSender messageSender;

	public Socket getSocketContext() {
		return clientSocket;
	}

	public boolean isConnect = false;
	public boolean isKeyChange = false;

	// ���� ����, �ʿ�� ����
	private final String hostname = "homework.islab.work";
	private final int port = 8080;

	public E2EEChat() throws Exception {

		clientSocket = new Socket();
		clientSocket.connect(new InetSocketAddress(hostname, port));

		InputStream stream = clientSocket.getInputStream();

		this.messageSender = new MessageSender(this);

		Thread senderThread = new Thread(this.messageSender);
		senderThread.start();

		while (true) {
			try {
				if (clientSocket.isClosed() || !senderThread.isAlive()) {
					break;
				}

				byte[] recvBytes = new byte[2048];
				int recvSize = stream.read(recvBytes);

				if (recvSize == 0) {
					continue;
				}

				String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

				parseReceiveData(recv);

			} catch (IOException ex) {
				System.out.println("���� ������ ���� �� ������ �߻��Ͽ����ϴ�.");
				break;
			}
		}

		try {
			System.out.println("�Է� �����尡 ����ɶ����� �����...");
			senderThread.join();

			if (clientSocket.isConnected()) {
				clientSocket.close();
			}
		} catch (InterruptedException ex) {
			System.out.println("����Ǿ����ϴ�.");
		}
	}

	public void parseReceiveData(String recvData) throws Exception {

		BufferedReader br = new BufferedReader(new StringReader(recvData));

		String method = br.readLine().split(" ")[1];

		if (method.equals("ACCEPT")) {

			this.isConnect = true;

		}

		else if (method.equals("KEYXCHG")) {

			String sender = br.readLine().split(":")[1];

			br.readLine();
			String algo = br.readLine();

			br.readLine();
			br.readLine();

			this.messageSender.keyChangeOk(this.dh.getSenderPublicKey(Base64.getDecoder().decode(br.readLine())),
					sender);
			this.aes = new Aes(this.dh.keyDB);
			
			System.out.println("ä�ù濡 ������ �� �ֽ��ϴ�. 2�� �����ּ���.");
		}

		else if (method.equals("KEYXCHGOK")) {

			// ���޹��� public key ����ؼ� phase ����� Ű���
			// ä�� ������ ������� while�� ����

			String sender = br.readLine();
			br.readLine();
			String algo = br.readLine();

			br.readLine();
			br.readLine();

			byte[] senderPublicKey = Base64.getDecoder().decode(br.readLine());

			dh.makeSecreteKey(senderPublicKey);
			this.aes = new Aes(this.dh.keyDB);
			this.isKeyChange = true;
		}

		else if (method.equals("MSGRECV")) {

			br.readLine();
			br.readLine();
			br.readLine();
			br.readLine();

			System.out.println("recvMsg : " + aes.decrytion(br.readLine())+"\n");
		}

		br.close();

	}

	// �ʿ��� ��� �߰��� �޼��带 �����Ͽ� ����մϴ�.

	public static void main(String[] args) throws Exception {
		try {
			new E2EEChat();
		} catch (UnknownHostException ex) {
			System.out.println("���� ����, ȣ��Ʈ ������ Ȯ���ϼ���.");
		} catch (IOException ex) {
			System.out.println("���� ��� �� ������ �߻��Ͽ����ϴ�.");
		}
	}
}

// ����� �Է��� ���� �޼��� ������ ���� Sender Runnable Class
// ���⿡�� �޼��� ���� ó���� �����մϴ�.
class MessageSender implements Runnable {

	E2EEChat clientContext;
	OutputStream socketOutputStream;
	Scanner scanner = new Scanner(System.in);

	private String credential = null;
	private String receiver = null;
	private String algo = "AEC-256-CBC";

	public MessageSender(E2EEChat context)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, InterruptedException {
		clientContext = context;

		Socket clientSocket = clientContext.getSocketContext();
		socketOutputStream = clientSocket.getOutputStream();

	}

	public void connectChat() throws IOException, InterruptedException {

		System.out.print("Credential �Է��ϼ��� : ");
		this.credential = scanner.nextLine();

		HashMap<String, String> headers = new HashMap<String, String>();
		headers.put("Credential", this.credential);

		byte[] payload = getPayloadByte(getMethodByte("CONNECT"), getHeaderByte(headers));

		socketOutputStream.write(payload, 0, payload.length);

		while (!this.clientContext.isConnect) {
			Thread.sleep(1000);
		}

		System.out.println("������ ���� �Ǿ����ϴ�.");

	}

	public void keyChange() throws InvalidKeyException, NoSuchAlgorithmException, IOException, InterruptedException {

		System.out.print("�����ڸ� �Է��ϼ���: ");
		String receiver = scanner.nextLine();

		this.receiver = receiver;

		HashMap<String, String> headers = new HashMap<String, String>();
		headers.put("Algo", this.algo);
		headers.put("From", this.credential);
		headers.put("To", receiver);

		byte[] publicKeyBase64 = Base64.getEncoder().encode(this.clientContext.dh.generatePublicKey());

		byte[] payload = getPayloadByte(getMethodByte("KEYXCHG"), getHeaderByte(headers), getBodyByte(publicKeyBase64));

		socketOutputStream.write(payload, 0, payload.length);

		while (!this.clientContext.isKeyChange) {
			Thread.sleep(1000);
		}

		System.out.println("ä���� ���۵˴ϴ�.\n");

		// ����Ű ����
		// Ű �ΰ� ����
		// ����Ȯ�� + ���� ������ �������� Ű����
		// Ű ���� ������ �̰ŷ� ���

	}

	public void keyChangeOk(byte[] publicKey, String receiver) throws IOException {
		this.receiver = receiver;
		HashMap<String, String> headers = new HashMap<String, String>();
		headers.put("Algo", this.algo);
		headers.put("From", this.credential);
		headers.put("To", this.receiver);

		byte[] publicKeyBase64 = Base64.getEncoder().encode(publicKey);

		byte[] payload = getPayloadByte(getMethodByte("KEYXCHGOK"), getHeaderByte(headers),
				getBodyByte(publicKeyBase64));

		socketOutputStream.write(payload, 0, payload.length);		

	}

	public void msgSend(String message) throws Exception {

		HashMap<String, String> headers = new HashMap<String, String>();
		headers.put("From", this.credential);
		headers.put("To", this.receiver);
		headers.put("Nonce", "my_msg");

		byte[] payload = getPayloadByte(getMethodByte("MSGSEND"), getHeaderByte(headers),
				getBodyByte(this.clientContext.aes.encrytion(message)));

		socketOutputStream.write(payload, 0, payload.length);

	}

	public byte[] getMethodByte(String method) {

		return ("3EPROTO" + " " + method + "\n").getBytes(StandardCharsets.UTF_8);
	}

	public byte[] getHeaderByte(HashMap<String, String> headers) {

		String headers_str = "";

		Set<String> keys = headers.keySet();

		for (String key : keys) {
			headers_str += key + ":" + headers.get(key) + "\n";
		}

		headers_str = headers_str.substring(0, headers_str.length() - 1);

		return headers_str.getBytes(StandardCharsets.UTF_8);

	}

	public byte[] getBodyByte(byte[] message) {

		byte[] body = new byte[2 + message.length];

		System.arraycopy("\n\n".getBytes(StandardCharsets.UTF_8), 0, body, 0, 2);
		System.arraycopy(message, 0, body, 2, message.length);

		return body;
	}

	public byte[] getPayloadByte(byte[] method, byte[] headers) {

		int size = method.length + headers.length;

		byte[] payload = new byte[size];

		System.arraycopy(method, 0, payload, 0, method.length);
		System.arraycopy(headers, 0, payload, method.length, headers.length);

		return payload;

	}

	public byte[] getPayloadByte(byte[] method, byte[] headers, byte[] body) {

		int size = method.length + headers.length + body.length;

		byte[] payload = new byte[size];

		System.arraycopy(method, 0, payload, 0, method.length);
		System.arraycopy(headers, 0, payload, method.length, headers.length);
		System.arraycopy(body, 0, payload, method.length + headers.length, body.length);

		return payload;
	}

	@Override
	public void run() {

		try {
			this.connectChat();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("����� �����ϼ���.\n");
		System.out.println("1. Ű ��ȯ 2. ä�ù� ����\n");
		String selected = scanner.nextLine();

		switch (selected) {

		case "1": {
			try {
				this.keyChange();
				System.out.println("ä�ù� ����\n");
			} catch (InvalidKeyException | NoSuchAlgorithmException | IOException | InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		case "2": {
		}

		}	

		while (true) {
			try {
				System.out.print("MESSAGE: \n");

				String message = scanner.nextLine().trim();
				msgSend(message);

			} catch (IOException ex) {
				break;
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		System.out.println("MessageSender runnable end");
	}

}
