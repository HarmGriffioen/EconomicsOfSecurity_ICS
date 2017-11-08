package PacketAnalyzer.PAN;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public class PortCheck {

	public static void main(String[] args) throws IOException {
		Map<Integer, Set<String>> map = new HashMap<Integer, Set<String>>();
		Map<String, Integer> sources = new HashMap<String, Integer>();
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new InputStreamReader(new FileInputStream("results.txt")));
		} catch (FileNotFoundException e) {
			System.out.println("File not found!");
			e.printStackTrace();
			System.exit(0);
		}

		String line = reader.readLine();
		while (line != null) {
			String[] res = line.split("\\s");
			int val = Integer.parseInt(res[0]);
			map.putIfAbsent(val, new HashSet<String>());
			sources.putIfAbsent(res[2], 0);
			sources.replace(res[2], sources.get(res[2])+1);
			map.get(val).add(res[1]);
			line = reader.readLine();
		}
		System.out.println("ModBus scan packets: " + map.get(502).size());
		System.out.println("Bacnet scan packets: " + map.get(47808).size());
		System.out.println("DNP3 scan packets: " + map.get(20000).size());
		System.out.println("EtherNet/IP scan packets: " + map.get(44818).size());
		System.out.println("Niagara Fox scan packets: " + (map.get(1911).size() + map.get(4911).size()));
		System.out.println("IEC-104 scan packets: " + map.get(2404).size());
		System.out.println("Red Lion scan packets: " + map.get(789).size());
		System.out.println("Siemens S7 scan packets: " + map.get(102).size());
		System.out.println("Amount of source ip's: " + sources.size());
		
		List<Entry<String, Integer>> destinationentries = new ArrayList<Map.Entry<String, Integer>>(sources.entrySet());
		Collections.sort(destinationentries, new Comparator<Map.Entry<String, Integer>>() {
		  public int compare(
		      Map.Entry<String, Integer> entry1, Map.Entry<String, Integer> entry2) {
		    return -1*entry1.getValue().compareTo(entry2.getValue());
		  }
		});

		for (int i = 0; i < 500; i++) {
			System.out.println(destinationentries.get(i).getValue());
			
		}
	}

}
