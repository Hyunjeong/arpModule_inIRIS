/**
 *    Copyright 2011, Big Switch Networks, Inc. 
 *    Originally created by David Erickson, Stanford University
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package etri.sdn.controller.util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import etri.sdn.controller.IListener;

/**
 * Maintain lists of listeners ordered by dependency.  
 * 
 * @author readams
 *
 */
public class ListenerDispatcher<U, T extends IListener<U>> {
	List<T> listeners = null;

	private void visit(List<T> newlisteners, U type, HashSet<T> visited, 
			List<T> ordering, T listener) {
		if (!visited.contains(listener)) {
			visited.add(listener);

			for (T i : newlisteners) {
				if (ispre(type, i, listener)) {
					visit(newlisteners, type, visited, ordering, i);
				}
			}
			ordering.add(listener);
		}
	}

	private boolean ispre(U type, T l1, T l2) {
		return (l2.isCallbackOrderingPrereq(type, l1.getName()) ||
				l1.isCallbackOrderingPostreq(type, l2.getName()));
	}

	/**
	 * Add a listener to the list of listeners
	 * @param listener
	 */
	 public void addListener(U type, T listener) {
		List<T> newlisteners = new ArrayList<T>();
		if (listeners != null)
			newlisteners.addAll(listeners);

		newlisteners.add(listener);
		// Find nodes without outgoing edges
		List<T> terminals = new ArrayList<T>(); 
		for (T i : newlisteners) {
			boolean isterm = true;
			for (T j : newlisteners) {
				if (ispre(type, i, j)) {
					isterm = false;
					break;
				}
			}
			if (isterm) {
				terminals.add(i);
			}
		}

		if (terminals.size() == 0) {
			Logger.stderr("No listener dependency solution: " +
					"No listeners without incoming dependencies");
			listeners = newlisteners;
			return;
		}

		// visit depth-first traversing in the opposite order from
		// the dependencies.  Note we will not generally detect cycles
		HashSet<T> visited = new HashSet<T>();
		List<T> ordering = new ArrayList<T>(); 
		for (T term : terminals) {
			visit(newlisteners, type, visited, ordering, term);
		}
		listeners = ordering;
	 }

	 /**
	  * Remove the given listener
	  * @param listener the listener to remove
	  */
	 public void removeListener(T listener) {
		 if (listeners != null) {
			 List<T> newlisteners = new ArrayList<T>();
			 newlisteners.addAll(listeners);
			 newlisteners.remove(listener);
			 listeners = newlisteners;
		 }
	 }

	 /**
	  * Clear all listeners
	  */
	 public void clearListeners() {
		 listeners = new ArrayList<T>();
	 }

	 /** 
	  * Get the ordered list of listeners ordered by dependencies 
	  * @return
	  */
	 public List<T> getOrderedListeners() {
		 return listeners;
	 }
}
